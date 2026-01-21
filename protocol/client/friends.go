package client

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/p2p"
	"github.com/banditmoscow1337/safem/protocol/profile"
)

// SendInvite sends a friend request to a target ID via the Rendezvous Server.
// It includes a cryptographic proof binding the keys to the specific target ID
// to prevent MITM attacks by the server.
func (c *Client) SendInvite(ctx context.Context, targetID string) {
	go func() {
		// Rate Limit: Block if we are sending too many invites too quickly
		if err := c.inviteLimiter.Wait(ctx); err != nil {
			c.Events.OnLog("[Error] Invite cancelled (Rate Limit): %v\n", err)
			return
		}

		// Prepare Invite Proof: [TargetID, SignPEM, EncPEM, Timestamp]
		signPEM := string(c.Profile.GetPublicKeyPEM())
		encPEM := string(c.Profile.GetEncPublicKeyPEM())
		ts := strconv.FormatInt(time.Now().Unix(), 10)

		dataToSign := fmt.Sprintf("%s%s%s%s", targetID, signPEM, encPEM, ts)
		sig, err := cryptolib.Sign([]byte(dataToSign), c.Peer.PrivKey)
		if err != nil {
			c.Events.OnLog("Failed to sign invite: %v\n", err)
			return
		}

		// Payload: [TargetID, SignPEM, EncPEM, Timestamp, Signature]
		payload := protocol.PackStrings(targetID, signPEM, encPEM, ts, string(sig))

		resp, err := c.Peer.Call(ctx, c.Profile.GetServerAddr(), protocol.OpInvite, payload)
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

// AcceptInvite confirms a pending friend request.
// It signs the acceptance to prove identity back to the inviter.
func (c *Client) AcceptInvite(ctx context.Context, targetID string) {
	c.Peer.KeysMu.RLock()
	inv, ok := c.Peer.PendingInvites[targetID]
	c.Peer.KeysMu.RUnlock()

	if !ok {
		c.Events.OnLog("No pending invite found for ID: %s\n", targetID)
		return
	}

	name := c.Peer.GetName(targetID)
	// Process the friend acceptance logic (saving keys, updating profile)
	c.AcceptFriendLogic(targetID, name, inv.Addr, inv.PEM, inv.EncPEM)

	// Prepare Acceptance Proof
	signPEM := string(c.Profile.GetPublicKeyPEM())
	encPEM := string(c.Profile.GetEncPublicKeyPEM())
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	dataToSign := fmt.Sprintf("%s%s%s%s", targetID, signPEM, encPEM, ts)
	sig, err := cryptolib.Sign([]byte(dataToSign), c.Peer.PrivKey)
	if err != nil {
		c.Events.OnLog("Failed to sign acceptance: %v\n", err)
		return
	}

	// Payload: [TargetID, SignPEM, EncPEM, Timestamp, Signature]
	payload := protocol.PackStrings(targetID, signPEM, encPEM, ts, string(sig))

	// Notify Server that invite was accepted (so it can forward finalize msg)
	go c.Peer.Call(ctx, c.Profile.GetServerAddr(), protocol.OpAcceptInvite, payload)

	// Clean up pending state
	c.Peer.KeysMu.Lock()
	delete(c.Peer.PendingInvites, targetID)
	c.Peer.KeysMu.Unlock()
}

// AcceptFriendLogic updates the local profile and P2P trust store with the new friend's details.
// It also triggers the initial handshake process.
func (c *Client) AcceptFriendLogic(id, name, addr, signPEM, encPEM string) {
	c.Peer.TrustPeer(id, []byte(signPEM), []byte(encPEM))
	c.Peer.MapPeer(addr, id, name)
	c.Peer.HolePunch(addr) // Attempt NAT traversal

	c.Profile.AddFriend(id, name, signPEM, encPEM)
	c.Profile.Save()

	go func() {
		// Collision Avoidance: High ID waits, Low ID initiates handshake.
		// This prevents both sides trying to handshake simultaneously.
		myID := c.Profile.GetID()
		delay := 200 * time.Millisecond
		if myID > id {
			delay = 2000 * time.Millisecond
		}
		time.Sleep(delay)

		// Check if session is already healthy
		if sess, ok := c.Peer.GetSession(id); ok {
			if time.Since(sess.LastRx) < 10*time.Second {
				// We are connected, so send our profile data immediately
				c.sendMyContent(context.Background(), id)
				return
			}
		}

		hsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := c.Peer.PerformHandshake(hsCtx, addr); err == nil {
			c.Peer.StartSessionMonitor()
			c.Events.OnFriendAdded(id, name)
			// Connection established: Sync Profile
			c.sendMyContent(context.Background(), id)
		} else {
			c.Events.OnLog("[System] Failed to handshake with new friend %s: %v\n", name, err)
		}
	}()
}

// RemoveFriend removes a friend from the local profile and terminates the connection.
func (c *Client) RemoveFriend(id string) error {
	c.Peer.Disconnect(id)
	c.Profile.RemoveFriend(id)

	return c.Profile.Save()
}

// GetSafetyNumber computes the safety number fingerprint for a specific friend.
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

// reconnectFriends iterates through the saved friend list and attempts to restore connections.
func (c *Client) reconnectFriends() {
	friends := c.Profile.ListFriends()
	for _, f := range friends {
		go func(friend profile.Friend) {
			c.Peer.TrustPeer(friend.ID, []byte(friend.PEM), []byte(friend.EncPEM))

			// Lookup up-to-date address via Server using dedicated OpQuery
			// This prevents triggering duplicate invite notifications on the target client.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Prepare Query Proof: [TargetID, SignPEM, EncPEM, Timestamp, Signature]
			// The server requires authentication to release address info.
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
				// Server Query Resp: [Status, TargetAddr, TargetSignPEM, TargetEncPEM]
				if len(strs) >= 2 && strs[0] == "OK" {
					targetAddr = strs[1]
				}
			}

			// Fallback to last known address if server lookup fails
			if targetAddr == "" {
				if existing, ok := c.Peer.GetSession(friend.ID); ok && existing.Addr != "" {
					targetAddr = existing.Addr
				} else {
					return
				}
			}

			// Try Direct Connection (P2P)
			c.Peer.MapPeer(targetAddr, friend.ID, friend.Name)
			c.Peer.HolePunch(targetAddr)

			hsCtx, hsCancel := context.WithTimeout(context.Background(), 3*time.Second)
			err = c.Peer.PerformHandshake(hsCtx, targetAddr)
			hsCancel()

			if err != nil {
				// FALLBACK TO RELAY
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
			
			// Connection Established: Sync Profile
			c.sendMyContent(context.Background(), friend.ID)

		}(f)
	}
}

// Handlers

// handleIncomingInvite processes a forwarded invite from the server.
// It verifies the cryptographic binding to ensure the invite was intended for us.
func (c *Client) handleIncomingInvite(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	// Payload: [SenderName, SenderAddr, SignPEM, EncPEM, TargetID, Timestamp, Signature]
	if len(args) < 7 {
		return nil, nil
	}

	name, addr, signPEM, encPEM, targetID, ts, sigStr := args[0], args[1], args[2], args[3], args[4], args[5], args[6]
	
	// Verify Intent: Is this invite for ME?
	if targetID != c.Profile.GetID() {
		return nil, fmt.Errorf("security: invite target mismatch (got %s, expected %s)", targetID, c.Profile.GetID())
	}

	// Verify Signature
	pub, err := cryptolib.PEMToPubKey([]byte(signPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid sender key")
	}

	dataToVerify := fmt.Sprintf("%s%s%s%s", targetID, signPEM, encPEM, ts)
	if err := cryptolib.Verify([]byte(dataToVerify), []byte(sigStr), pub); err != nil {
		return nil, fmt.Errorf("security: invalid invite signature")
	}

	// Check Timestamp freshness (e.g., 5 min window)
	tsVal, _ := strconv.ParseInt(ts, 10, 64)
	if time.Since(time.Unix(tsVal, 0)) > 5*time.Minute {
		return nil, fmt.Errorf("security: expired invite")
	}

	id := cryptolib.Fingerprint(pub)

	// If we are already connected, ignore the invite trigger but update connection info
	if _, ok := c.Profile.GetFriend(id); ok {
		c.Peer.MapPeer(addr, id, name)
		c.Peer.TrustPeer(id, []byte(signPEM), []byte(encPEM))
		c.Peer.HolePunch(addr)

		// Check active session health before triggering handshake
		if sess, ok := c.Peer.GetSession(id); ok {
			if time.Since(sess.LastRx) < 10*time.Second {
				// We are healthy, so ensure we are synced
				c.sendMyContent(context.Background(), id)
				return protocol.PackStrings("ACK"), nil
			}
		}

		go func() {
			// Collision Avoidance logic
			myID := c.Profile.GetID()
			delay := 200 * time.Millisecond
			if myID > id {
				delay = 2000 * time.Millisecond
			}
			time.Sleep(delay)

			hsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c.Peer.PerformHandshake(hsCtx, addr)
			
			// Connection Established: Sync
			c.sendMyContent(context.Background(), id)
		}()

		return protocol.PackStrings("ACK"), nil
	}

	// New Invite: Store pending state
	c.Peer.KeysMu.Lock()
	c.Peer.PendingInvites[id] = p2p.InviteData{Addr: addr, PEM: signPEM, EncPEM: encPEM}
	c.Peer.KeysMu.Unlock()
	c.Peer.MapPeer(addr, id, name)

	c.Events.OnInviteReceived(id, name, addr, signPEM)
	return protocol.PackStrings("ACK"), nil
}

// handleInviteFinalized is called when the other user accepts OUR invite.
func (c *Client) handleInviteFinalized(remote *net.UDPAddr, data []byte) ([]byte, error) {
	args := protocol.UnpackStrings(data)
	// Payload: [SenderName, SenderAddr, SignPEM, EncPEM, TargetID, Timestamp, Signature]
	if len(args) < 7 {
		return nil, nil
	}

	name, addr, signPEM, encPEM, targetID, ts, sigStr := args[0], args[1], args[2], args[3], args[4], args[5], args[6]

	// Verify Intent
	if targetID != c.Profile.GetID() {
		return nil, fmt.Errorf("security: acceptance target mismatch")
	}

	// Verify Signature
	pub, err := cryptolib.PEMToPubKey([]byte(signPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid sender key")
	}

	dataToVerify := fmt.Sprintf("%s%s%s%s", targetID, signPEM, encPEM, ts)
	if err := cryptolib.Verify([]byte(dataToVerify), []byte(sigStr), pub); err != nil {
		return nil, fmt.Errorf("security: invalid acceptance signature")
	}

	id := cryptolib.Fingerprint(pub)

	if sess, ok := c.Peer.GetSession(id); ok {
		if time.Since(sess.LastRx) < 10*time.Second {
			return protocol.PackStrings("ACK"), nil
		}
	}

	// Finalize friend addition
	c.AcceptFriendLogic(id, name, addr, signPEM, encPEM)
	return protocol.PackStrings("ACK"), nil
}