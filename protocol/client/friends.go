package client

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/p2p"
	"github.com/banditmoscow1337/safem/protocol/profile"
)

// SendInvite sends an encrypted friend request to a target ID via the Rendezvous Server.
func (c *Client) SendInvite(ctx context.Context, targetID string) {
	go func() {
		// Rate Limit: Block if we are sending too many invites too quickly
		if err := c.inviteLimiter.Wait(ctx); err != nil {
			c.Events.OnLog("[Error] Invite cancelled (Rate Limit): %v\n", err)
			return
		}

		// 1. LOOKUP PHASE: Get Target's Encryption Key from Server
		c.Events.OnLog("[Invite] Resolving keys for %s...\n", targetID)

		mySignPEM := string(c.Profile.GetPublicKeyPEM())
		myEncPEM := string(c.Profile.GetEncPublicKeyPEM())
		ts := strconv.FormatInt(time.Now().Unix(), 10)

		// Sign the query to authenticate ourselves to the server
		queryData := fmt.Sprintf("%s%s%s%s", targetID, mySignPEM, myEncPEM, ts)
		querySig, _ := cryptolib.Sign([]byte(queryData), c.Peer.PrivKey)

		queryPayload := protocol.PackStrings(targetID, mySignPEM, myEncPEM, ts, string(querySig))
		queryResp, err := c.Peer.Call(ctx, c.Profile.GetServerAddr(), protocol.OpQuery, queryPayload)
		if err != nil {
			c.Events.OnLog("[Invite] Key lookup failed: %v\n", err)
			return
		}

		qArgs := protocol.UnpackStrings(queryResp)
		if len(qArgs) < 4 || qArgs[0] != "OK" {
			c.Events.OnLog("[Invite] User not found or lookup failed.\n")
			return
		}

		// Target Keys
		targetEncPEM := qArgs[3]
		targetEncPub, err := cryptolib.PEMToEncPubKey([]byte(targetEncPEM))
		if err != nil {
			c.Events.OnLog("[Invite] Invalid target encryption key.\n")
			return
		}

		// Parse Write Token (Sealed Sender) if available
		if len(qArgs) >= 11 {
			writeToken := qArgs[10]
			c.Peer.SetWriteToken(targetID, writeToken)
		}

		// 2. ENCRYPTION PHASE: Prepare Inner Payload (Identity Data)
		myName := c.Profile.GetNickname()
		myID := c.Profile.GetID()

		innerDataToSign := fmt.Sprintf("%s%s%s%s%s", myID, myName, mySignPEM, myEncPEM, ts)
		innerSig, _ := cryptolib.Sign([]byte(innerDataToSign), c.Peer.PrivKey)

		innerPayload := protocol.PackStrings(myID, myName, mySignPEM, myEncPEM, ts, string(innerSig))

		// Encrypt for Bob
		encryptedBlob, err := cryptolib.EncryptHybrid(innerPayload, targetEncPub, []byte("INVITE"))
		if err != nil {
			c.Events.OnLog("[Invite] Encryption failed: %v\n", err)
			return
		}

		blobHex := hex.EncodeToString(encryptedBlob)

		// 3. ROUTING PHASE: Prepare Outer Payload for Server
		outerDataToSign := fmt.Sprintf("%s%s%s", targetID, blobHex, ts)
		outerSig, _ := cryptolib.Sign([]byte(outerDataToSign), c.Peer.PrivKey)

		outerPayload := protocol.PackStrings(targetID, blobHex, ts, string(outerSig))

		c.Events.OnLog("[Invite] Sending encrypted invite...\n")
		resp, err := c.Peer.Call(ctx, c.Profile.GetServerAddr(), protocol.OpInvite, outerPayload)
		if err != nil {
			c.Events.OnLog("Invite error: %v\n", err)
			return
		}

		strs := protocol.UnpackStrings(resp)
		if len(strs) > 0 {
			c.Events.OnLog("[Server]: %s\n", strs[0])
		}
	}()
}

// AcceptInvite confirms a pending friend request securely.
func (c *Client) AcceptInvite(ctx context.Context, targetID string) {
	c.Peer.KeysMu.RLock()
	inv, ok := c.Peer.PendingInvites[targetID]
	c.Peer.KeysMu.RUnlock()

	if !ok {
		c.Events.OnLog("No pending invite found for ID: %s\n", targetID)
		return
	}

	go func() {
		// RESOLVE ADDRESS
		realAddr := inv.Addr
		if realAddr == "" {
			var err error
			lCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			realAddr, err = c.lookupPeerAddress(lCtx, targetID)
			cancel()
			if err != nil {
				c.Events.OnLog("[Error] Could not resolve address for %s: %v. Cannot accept invite.\n", targetID, err)
				return
			}
		}

		name := c.Peer.GetName(targetID)

		c.AcceptFriendLogic(targetID, name, realAddr, inv.PEM, inv.EncPEM)

		// Encrypt Acceptance for Alice
		targetEncPub, err := cryptolib.PEMToEncPubKey([]byte(inv.EncPEM))
		if err != nil {
			c.Events.OnLog("Cannot accept: invalid sender enc key\n")
			return
		}

		myID := c.Profile.GetID()
		myName := c.Profile.GetNickname()
		mySignPEM := string(c.Profile.GetPublicKeyPEM())
		myEncPEM := string(c.Profile.GetEncPublicKeyPEM())
		ts := strconv.FormatInt(time.Now().Unix(), 10)

		innerDataToSign := fmt.Sprintf("%s%s%s%s%s", myID, myName, mySignPEM, myEncPEM, ts)
		innerSig, _ := cryptolib.Sign([]byte(innerDataToSign), c.Peer.PrivKey)

		innerPayload := protocol.PackStrings(myID, myName, mySignPEM, myEncPEM, ts, string(innerSig))

		encryptedBlob, _ := cryptolib.EncryptHybrid(innerPayload, targetEncPub, []byte("ACCEPT"))
		blobHex := hex.EncodeToString(encryptedBlob)

		outerDataToSign := fmt.Sprintf("%s%s%s", targetID, blobHex, ts)
		outerSig, _ := cryptolib.Sign([]byte(outerDataToSign), c.Peer.PrivKey)

		payload := protocol.PackStrings(targetID, blobHex, ts, string(outerSig))

		c.Peer.Call(ctx, c.Profile.GetServerAddr(), protocol.OpAcceptInvite, payload)

		c.Peer.KeysMu.Lock()
		delete(c.Peer.PendingInvites, targetID)
		c.Peer.KeysMu.Unlock()
	}()
}

// AcceptFriendLogic updates the local profile and P2P trust store with the new friend's details.
func (c *Client) AcceptFriendLogic(id, name, addr, signPEM, encPEM string) {
	c.Peer.TrustPeer(id, []byte(signPEM), []byte(encPEM))
	c.Peer.MapPeer(addr, id, name)
	c.Peer.HolePunch(addr)

	c.Profile.AddFriend(id, name, signPEM, encPEM)
	c.Profile.Save()

	go func() {
		myID := c.Profile.GetID()
		delay := 200 * time.Millisecond
		if myID > id {
			delay = 2000 * time.Millisecond
		}
		time.Sleep(delay)

		if sess, ok := c.Peer.GetSession(id); ok {
			if time.Since(sess.LastRx) < 10*time.Second {
				c.sendMyContent(context.Background(), id)
				return
			}
		}

		hsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := c.Peer.PerformHandshake(hsCtx, addr); err == nil {
			c.Peer.StartSessionMonitor()
			c.Events.OnFriendAdded(id, name)
			c.sendMyContent(context.Background(), id)
		} else {
			c.Events.OnLog("[System] Failed to handshake with new friend %s: %v\n", name, err)
		}
	}()
}

func (c *Client) RemoveFriend(id string) error {
	c.Peer.Disconnect(id)
	c.Profile.RemoveFriend(id)
	return c.Profile.Save()
}

func (c *Client) GetSafetyNumber(friendID string) (string, error) {
	friend, ok := c.Profile.GetFriend(friendID)
	if !ok {
		return "", fmt.Errorf("friend not found")
	}

	friendKey, err := cryptolib.PEMToPubKey([]byte(friend.PEM))
	if err != nil {
		return "", fmt.Errorf("invalid friend key")
	}

	myKeyPEM := c.Profile.GetPublicKeyPEM()
	myKey, err := cryptolib.PEMToPubKey(myKeyPEM)
	if err != nil {
		return "", fmt.Errorf("invalid local key")
	}

	return cryptolib.ComputeSafetyNumber(myKey, friendKey), nil
}

// lookupPeerAddress asks the server for the current address and Sealed Sender token of a peer ID.
func (c *Client) lookupPeerAddress(ctx context.Context, targetID string) (string, error) {
	signPEM := string(c.Profile.GetPublicKeyPEM())
	encPEM := string(c.Profile.GetEncPublicKeyPEM())
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	dataToSign := fmt.Sprintf("%s%s%s%s", targetID, signPEM, encPEM, ts)
	sig, err := cryptolib.Sign([]byte(dataToSign), c.Peer.PrivKey)
	if err != nil {
		return "", err
	}

	payload := protocol.PackStrings(targetID, signPEM, encPEM, ts, string(sig))

	resp, err := c.Peer.Call(ctx, c.Profile.GetServerAddr(), protocol.OpQuery, payload)
	if err != nil {
		return "", err
	}

	strs := protocol.UnpackStrings(resp)
	if len(strs) < 2 || strs[0] != "OK" {
		return "", fmt.Errorf("lookup failed or user not found")
	}

	// Save Write Token if present (Index 10)
	if len(strs) >= 11 {
		c.Peer.SetWriteToken(targetID, strs[10])
	}

	// [OK, Addr, SignPEM, EncPEM, Root, Proof, Index, Total, STH_Sig, TS, WriteToken]
	return strs[1], nil
}

// reconnectFriends iterates through the saved friend list and attempts to restore connections.
func (c *Client) reconnectFriends() {
	friends := c.Profile.ListFriends()

	_, serverSignPEM, _ := c.Profile.GetServer()
	var serverPub ed25519.PublicKey
	if serverSignPEM != "" {
		serverPub, _ = cryptolib.PEMToPubKey([]byte(serverSignPEM))
	}

	for _, f := range friends {
		go func(friend profile.Friend) {
			c.Peer.TrustPeer(friend.ID, []byte(friend.PEM), []byte(friend.EncPEM))

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			signPEM := string(c.Profile.GetPublicKeyPEM())
			encPEM := string(c.Profile.GetEncPublicKeyPEM())
			ts := strconv.FormatInt(time.Now().Unix(), 10)

			dataToSign := fmt.Sprintf("%s%s%s%s", friend.ID, signPEM, encPEM, ts)
			sig, _ := cryptolib.Sign([]byte(dataToSign), c.Peer.PrivKey)

			payload := protocol.PackStrings(friend.ID, signPEM, encPEM, ts, string(sig))

			resp, err := c.Peer.Call(ctx, c.Profile.GetServerAddr(), protocol.OpQuery, payload)
			var targetAddr string

			if err == nil {
				strs := protocol.UnpackStrings(resp)
				// Server Query Resp: [Status, Addr, SignPEM, EncPEM, Root, Proof, Index, Total, STH_Sig, TS, WriteToken]

				if len(strs) >= 10 && strs[0] == "OK" {
					targetAddr = strs[1]
					targetSign := strs[2]
					targetEnc := strs[3]
					rootHex := strs[4]
					proofStr := strs[5]
					idxStr := strs[6]
					totalStr := strs[7]
					sthSigHex := strs[8]
					sthTs := strs[9]

					// Save Write Token for Relay Authentication
					if len(strs) >= 11 {
						c.Peer.SetWriteToken(friend.ID, strs[10])
					}

					// --- cryptolib Verification ---
					if serverPub != nil {
						sthSig, _ := hex.DecodeString(sthSigHex)
						sthData := []byte(rootHex + sthTs)
						if err := cryptolib.Verify(sthData, sthSig, serverPub); err != nil {
							c.Events.OnLog("[Security] STH Signature Failed for %s. Server may be compromised!\n", friend.Name)
							return
						}
					}

					leafHash := cryptolib.CalculateLeafHash(friend.ID, targetSign, targetEnc)
					rootBytes, _ := hex.DecodeString(rootHex)

					var proof [][]byte
					if proofStr != "" {
						parts := strings.Split(proofStr, ",")
						for _, p := range parts {
							b, _ := hex.DecodeString(p)
							proof = append(proof, b)
						}
					}

					idx, _ := strconv.Atoi(idxStr)
					total, _ := strconv.Atoi(totalStr)

					if !cryptolib.VerifyMerkleProof(rootBytes, leafHash, proof, idx, total) {
						c.Events.OnLog("[Security] Key cryptolib Proof Failed for %s! Possible MITM.\n", friend.Name)
						return
					}
				}
			}

			if targetAddr == "" {
				if existing, ok := c.Peer.GetSession(friend.ID); ok && existing.Addr != "" {
					targetAddr = existing.Addr
				} else {
					return
				}
			}

			c.Peer.MapPeer(targetAddr, friend.ID, friend.Name)
			c.Peer.HolePunch(targetAddr)

			hsCtx, hsCancel := context.WithTimeout(context.Background(), 3*time.Second)
			err = c.Peer.PerformHandshake(hsCtx, targetAddr)
			hsCancel()

			if err != nil {
				c.Events.OnLog("[Network] Direct connection to %s failed. Trying Relay...\n", friend.Name)

				serverAddr := c.Profile.GetServerAddr()
				if serverAddr != "" {
					relayCtx, relayCancel := context.WithTimeout(context.Background(), 5*time.Second)
					relayErr := c.Peer.PerformRelayedHandshake(relayCtx, friend.ID, serverAddr)
					relayCancel()

					if relayErr != nil {
						c.Events.OnLog("[Network] Relay connection failed: %v\n", relayErr)
						return
					}
					c.Events.OnLog("[Network] Connected to %s via Relay.\n", friend.Name)
				} else {
					c.Events.OnLog("[Network] No relay available.\n")
					return
				}
			} else {
				c.Events.OnLog("[Network] Connected to %s directly.\n", friend.Name)
			}

			c.Events.OnFriendStatus(friend.ID, true)
			c.Peer.StartSessionMonitor()
			c.sendMyContent(context.Background(), friend.ID)

		}(f)
	}
}

// Handlers

func (c *Client) handleIncomingInvite(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	if len(args) < 3 {
		return nil, nil
	}
	senderID, blobHex, ts := args[0], args[1], args[2]

	blob, err := hex.DecodeString(blobHex)
	if err != nil {
		return nil, fmt.Errorf("malformed hex")
	}

	encPriv, _ := cryptolib.ParseEncPrivateKey(string(c.Profile.GetEncPrivateKeyPEM()))
	decryptedBytes, err := cryptolib.DecryptHybrid(blob, encPriv, []byte("INVITE"))
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	innerArgs := protocol.UnpackStrings(decryptedBytes)
	if len(innerArgs) < 6 {
		return nil, fmt.Errorf("malformed inner payload")
	}

	incID, name, signPEM, encPEM, innerTS, sigStr := innerArgs[0], innerArgs[1], innerArgs[2], innerArgs[3], innerArgs[4], innerArgs[5]

	if incID != senderID {
		return nil, fmt.Errorf("security: sender ID mismatch in encrypted payload")
	}

	tsVal, _ := strconv.ParseInt(ts, 10, 64)
	innerTSVal, _ := strconv.ParseInt(innerTS, 10, 64)
	if time.Since(time.Unix(tsVal, 0)) > 10*time.Minute || time.Since(time.Unix(innerTSVal, 0)) > 10*time.Minute {
		return nil, fmt.Errorf("security: invite expired")
	}

	pub, err := cryptolib.PEMToPubKey([]byte(signPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid sender key")
	}

	dataToVerify := fmt.Sprintf("%s%s%s%s%s", incID, name, signPEM, encPEM, innerTS)
	if err := cryptolib.Verify([]byte(dataToVerify), []byte(sigStr), pub); err != nil {
		return nil, fmt.Errorf("security: invalid inner invite signature")
	}

	id := cryptolib.Fingerprint(pub)

	if _, ok := c.Profile.GetFriend(id); ok {
		c.Peer.TrustPeer(id, []byte(signPEM), []byte(encPEM))

		go func() {
			myID := c.Profile.GetID()
			delay := 200 * time.Millisecond
			if myID > id {
				delay = 2000 * time.Millisecond
			}
			time.Sleep(delay)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			addr, err := c.lookupPeerAddress(ctx, id)
			if err == nil {
				c.Peer.MapPeer(addr, id, name)
				c.Peer.HolePunch(addr)
				c.Peer.PerformHandshake(ctx, addr)
				c.sendMyContent(context.Background(), id)
			}
		}()

		return protocol.PackStrings("ACK"), nil
	}

	c.Peer.KeysMu.Lock()
	c.Peer.PendingInvites[id] = p2p.InviteData{Addr: "", PEM: signPEM, EncPEM: encPEM}
	c.Peer.KeysMu.Unlock()
	c.Peer.MapPeer("", id, name)

	c.Events.OnInviteReceived(id, name, "via-server", signPEM)
	return protocol.PackStrings("ACK"), nil
}

func (c *Client) handleInviteFinalized(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	if len(args) < 3 {
		return nil, nil
	}
	senderID, blobHex, ts := args[0], args[1], args[2]

	blob, err := hex.DecodeString(blobHex)
	if err != nil {
		return nil, fmt.Errorf("malformed hex")
	}

	encPriv, _ := cryptolib.ParseEncPrivateKey(string(c.Profile.GetEncPrivateKeyPEM()))
	decryptedBytes, err := cryptolib.DecryptHybrid(blob, encPriv, []byte("ACCEPT"))
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	innerArgs := protocol.UnpackStrings(decryptedBytes)
	if len(innerArgs) < 6 {
		return nil, nil
	}
	incID, name, signPEM, encPEM, innerTS, sigStr := innerArgs[0], innerArgs[1], innerArgs[2], innerArgs[3], innerArgs[4], innerArgs[5]

	if incID != senderID {
		return nil, fmt.Errorf("security: sender ID mismatch")
	}

	tsVal, _ := strconv.ParseInt(ts, 10, 64)
	if time.Since(time.Unix(tsVal, 0)) > 10*time.Minute {
		return nil, fmt.Errorf("security: acceptance expired")
	}

	pub, err := cryptolib.PEMToPubKey([]byte(signPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid sender key")
	}

	dataToVerify := fmt.Sprintf("%s%s%s%s%s", incID, name, signPEM, encPEM, innerTS)
	if err := cryptolib.Verify([]byte(dataToVerify), []byte(sigStr), pub); err != nil {
		return nil, fmt.Errorf("security: invalid acceptance signature")
	}

	id := cryptolib.Fingerprint(pub)

	if sess, ok := c.Peer.GetSession(id); ok {
		if time.Since(sess.LastRx) < 10*time.Second {
			return protocol.PackStrings("ACK"), nil
		}
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		addr, err := c.lookupPeerAddress(ctx, id)
		if err != nil {
			c.Events.OnLog("Failed to resolve address for new friend %s: %v", name, err)
			return
		}

		c.AcceptFriendLogic(id, name, addr, signPEM, encPEM)
	}()

	return protocol.PackStrings("ACK"), nil
}