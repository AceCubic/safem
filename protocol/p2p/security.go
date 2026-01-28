package p2p

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

// HandshakeWindow defines the time window in which a handshake attempt is valid.
const HandshakeWindow = 30 * time.Second

// MaxHandshakeCacheSize limits the number of tracked handshake signatures to prevent memory exhaustion.
// 5000 entries is sufficient for high throughput while keeping memory footprint low (~0.5MB).
const MaxHandshakeCacheSize = 5000

// InviteData holds the credentials received during a friend invite.
type InviteData struct {
	Addr   string // Network Address
	PEM    string // Signing Public Key
	EncPEM string // Encryption Public Key
}

// deriveChainKeys derives initial sending and receiving chain keys from the shared secret.
// Determining which key corresponds to which chain relies on a deterministic comparison of Peer IDs.
func deriveChainKeys(secret []byte, myID, peerID string) (rootKey, sendChainKey, recvChainKey []byte, err error) {
	// Root Key is derived directly from the Master Secret (HKDF or similar simple derivation for init)
	rootKey, err = cryptolib.DeriveSessionKey(secret, []byte("Safem Root Key"))
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive two symmetric keys for the initial chains
	keyA, err := cryptolib.DeriveSessionKey(secret, []byte("Safem Chain A"))
	if err != nil {
		return nil, nil, nil, err
	}

	keyB, err := cryptolib.DeriveSessionKey(secret, []byte("Safem Chain B"))
	if err != nil {
		return nil, nil, nil, err
	}

	// Deterministic assignment based on ID sort order
	if myID < peerID {
		return rootKey, keyA, keyB, nil
	}
	return rootKey, keyB, keyA, nil
}

// deriveWireID calculates the session identifier.
// 0 is reserved for cleartext, so we ensure the result is never 0.
func deriveWireID(secret []byte) (uint64, error) {
	key, err := cryptolib.DeriveSessionKey(secret, []byte("Safem WireID"))
	if err != nil {
		return 0, err
	}

	val := binary.BigEndian.Uint64(key[:8])
	if val == 0 {
		return 1, nil
	}
	return val, nil
}

// PerformHandshake initiates an Ephemeral-First Authenticated Handshake with a target peer.
// It establishes a secure session using ECDH for key exchange and Ed25519 for identity verification.
//
// Mechanism:
// 1. Checks if a handshake is already in flight (SingleFlight pattern).
// 2. Generates an ephemeral key pair.
// 3. Encrypts a handshake payload containing identity proof using a derived tunnel key.
// 4. Sends the payload and waits for a response.
// 5. If successful, initializes the Double Ratchet session state.
func (p *Peer) PerformHandshake(ctx context.Context, targetAddr string) error {
	p.handshakeInFlightMu.Lock()
	if ch, ok := p.handshakeInFlight[targetAddr]; ok {
		p.handshakeInFlightMu.Unlock()
		// Another goroutine is already handshaking with this peer. Wait for them.
		select {
		case <-ch:
			// The leader finished. Check if they successfully established the session.
			if _, ok := p.GetSessionByAddr(targetAddr); ok {
				return nil
			}
			return errors.New("concurrent handshake failed or did not establish session")
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// We are the leader. Create channel to block followers.
	ch := make(chan struct{})
	p.handshakeInFlight[targetAddr] = ch
	p.handshakeInFlightMu.Unlock()

	defer func() {
		p.handshakeInFlightMu.Lock()
		delete(p.handshakeInFlight, targetAddr)
		p.handshakeInFlightMu.Unlock()
		close(ch)
	}()

	p.KeysMu.RLock()
	id, knownID := p.peerIDs[targetAddr]
	var targetEncPub *ecdh.PublicKey
	var targetSignPub ed25519.PublicKey

	if knownID {
		targetEncPub = p.encIdentities[id]
		targetSignPub = p.identities[id]
	}
	p.KeysMu.RUnlock()

	if targetEncPub == nil || targetSignPub == nil {
		return errors.New("cannot handshake: peer keys unknown")
	}

	// Generate Ephemeral Key (E_init)
	ephemPriv, ephemPub, err := cryptolib.GenerateECDH()
	if err != nil {
		return err
	}
	ephemPubBytes := ephemPub.Bytes()

	// Establish Encrypted Tunnel for Handshake (E_init * S_resp)
	tunnelSecret, err := ephemPriv.ECDH(targetEncPub)
	if err != nil {
		return err
	}

	tunnelKey, err := cryptolib.DeriveSessionKey(tunnelSecret, []byte("Safem Handshake Tunnel"))
	if err != nil {
		return err
	}

	// Prepare Secured Payload (ID + PubKey + TS + Sig)
	ts := time.Now().Unix()
	myID := cryptolib.Fingerprint(p.PubKey)
	pubKeyBytes := []byte(p.PubKey)

	sigData := []byte(fmt.Sprintf("%s%d%x", myID, ts, ephemPubBytes))
	sig, err := cryptolib.Sign(sigData, p.PrivKey)
	if err != nil {
		return err
	}

	innerBuf := new(bytes.Buffer)
	binary.Write(innerBuf, binary.BigEndian, uint16(len(myID)))
	innerBuf.WriteString(myID)
	binary.Write(innerBuf, binary.BigEndian, uint16(len(pubKeyBytes)))
	innerBuf.Write(pubKeyBytes)
	binary.Write(innerBuf, binary.BigEndian, uint64(ts))
	binary.Write(innerBuf, binary.BigEndian, uint16(len(sig)))
	innerBuf.Write(sig)

	// Encrypt Payload
	tunnelAEAD, err := cryptolib.NewAEAD(tunnelKey)
	if err != nil {
		return err
	}

	nonce, _ := cryptolib.GenerateRandomBytes(12)
	ciphertext := tunnelAEAD.Seal(nil, nonce, innerBuf.Bytes(), nil)

	// sConstruct Packet & Send with Cookie Support
	packHandshake := func(cookie []byte) []byte {
		buf := new(bytes.Buffer)
		if len(cookie) > 0 {
			buf.WriteByte(byte(len(cookie)))
			buf.Write(cookie)
		} else {
			buf.WriteByte(0)
		}
		buf.Write(ephemPubBytes)
		buf.Write(nonce)
		buf.Write(ciphertext)
		return buf.Bytes()
	}

	var respPayload []byte
	reqPayload := packHandshake(nil)

	// Try up to 2 times
	for range 2 {
		respPayload, err = p.Call(ctx, targetAddr, protocol.OpHandshake, reqPayload)
		if err != nil {
			return err
		}

		if bytes.HasPrefix(respPayload, []byte("CK")) {
			cookie := respPayload[2:]
			reqPayload = packHandshake(cookie)
			continue
		}
		break
	}

	// Process Response
	return p.finishHandshake(id, targetAddr, respPayload, ephemPriv, ephemPubBytes, targetSignPub, false, "")
}

// finishHandshake handles the common logic of verifying the responder's proof and installing session keys.
func (p *Peer) finishHandshake(id, addr string, respPayload []byte, ephemPriv *ecdh.PrivateKey, ephemPubBytes []byte, targetSignPub ed25519.PublicKey, relayed bool, relayAddr string) error {
	if bytes.HasPrefix(respPayload, []byte("CK")) {
		return errors.New("handshake failed: cookie rejected")
	}

	if len(respPayload) < 32+12 {
		return errors.New("response too short")
	}

	respEphemPubBytes := respPayload[0:32]
	respNonce := respPayload[32 : 32+12]
	respCiphertext := respPayload[32+12:]

	respEphemPub, err := ecdh.X25519().NewPublicKey(respEphemPubBytes)
	if err != nil {
		return fmt.Errorf("invalid response ephemeral key: %v", err)
	}

	// Derive Final Session Keys (E_init * E_resp)
	sessionSecret, err := ephemPriv.ECDH(respEphemPub)
	if err != nil {
		return err
	}

	// Temporary key just to decrypt the handshake response
	handshakeResKey, err := cryptolib.DeriveSessionKey(sessionSecret, []byte("Safem Handshake Resp"))
	if err != nil {
		return err
	}

	// Decrypt Response
	handshakeAEAD, err := cryptolib.NewAEAD(handshakeResKey)
	if err != nil {
		return err
	}

	respDec, err := handshakeAEAD.Open(nil, respNonce, respCiphertext, nil)
	if err != nil {
		return fmt.Errorf("response decryption failed: %v", err)
	}

	// Unpack Response Payload
	if len(respDec) < 2 {
		return errors.New("malformed response payload")
	}
	srvIDLen := binary.BigEndian.Uint16(respDec[0:2])
	offset := 2 + int(srvIDLen) + 8 + 2

	if len(respDec) < offset {
		return errors.New("malformed response payload (truncated)")
	}

	srvID := string(respDec[2 : 2+int(srvIDLen)])
	srvTS := int64(binary.BigEndian.Uint64(respDec[2+int(srvIDLen) : 2+int(srvIDLen)+8]))
	srvSigLen := binary.BigEndian.Uint16(respDec[2+int(srvIDLen)+8 : 2+int(srvIDLen)+8+2])

	if len(respDec) < offset+int(srvSigLen) {
		return errors.New("malformed response payload (sig truncated)")
	}
	srvSig := respDec[offset : offset+int(srvSigLen)]

	if srvID != id {
		return fmt.Errorf("id mismatch: expected %s, got %s", id, srvID)
	}

	verifyData := []byte(fmt.Sprintf("%s%d%x%x", srvID, srvTS, ephemPubBytes, respEphemPubBytes))
	if err := cryptolib.Verify(verifyData, srvSig, targetSignPub); err != nil {
		return fmt.Errorf("server signature invalid: %v", err)
	}

	// Initialize Double Ratchet Session
	myID := cryptolib.Fingerprint(p.PubKey)
	rootKey, sendChainKey, recvChainKey, err := deriveChainKeys(sessionSecret, myID, srvID)
	if err != nil {
		return err
	}

	wireID, err := deriveWireID(sessionSecret)
	if err != nil {
		return err
	}

	name := p.GetName(srvID)

	p.KeysMu.Lock()
	if !relayed {
		p.peerIDs[addr] = srvID
	}
	p.KeysMu.Unlock()

	sRaw, _ := p.Sessions.LoadOrStore(srvID, &Session{
		ID:         srvID,
		Addr:       addr,
		Name:       name,
		LastRx:     time.Now(),
		LastRotate: time.Now(),
		WireID:     wireID,
	})
	s := sRaw.(*Session)

	s.Lock()
	s.Addr = addr
	// Set Initial Ratchet State
	s.RootKey = rootKey
	s.SendChainKey = sendChainKey
	s.RecvChainKey = recvChainKey

	s.InitRatchet(ephemPriv, respEphemPub)
	s.LastRx = time.Now()
	s.TxCount = 0
	s.RxCount = 0
	s.SkippedMessageKeys = make(map[uint64][]byte) // Reset skipped keys

	// Relay Config
	s.IsRelayed = relayed
	s.RelayAddr = relayAddr

	s.Unlock()
	// Update WireID Mapping
	p.WireIDSessions.Store(wireID, s)

	p.replayMu.Lock()
	delete(p.replayStates, srvID)
	p.replayMu.Unlock()

	mode := "Direct"
	if relayed {
		mode = "Relayed"
	}

	p.Logger("[Security] %s Handshake complete with %s. Secure WireID: %x\n", mode, name, wireID)
	return nil
}

// handleHandshake processes an incoming direct handshake request.
func (p *Peer) handleHandshake(remote *net.UDPAddr, data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, errors.New("short packet")
	}
	cookieLen := int(data[0])
	if len(data) < 1+cookieLen+32+12 {
		return nil, errors.New("truncated packet")
	}

	cookie := data[1 : 1+cookieLen]
	ephemPubBytes := data[1+cookieLen : 1+cookieLen+32]
	nonce := data[1+cookieLen+32 : 1+cookieLen+32+12]
	ciphertext := data[1+cookieLen+32+12:]

	if !p.verifyCookie(remote.IP.String(), cookie) {
		return append([]byte("CK"), p.generateCookie(remote.IP.String())...), nil
	}

	out, _, err := p.processIncomingHandshake(remote.String(), ephemPubBytes, nonce, ciphertext, false, "")
	return out, err
}

func (p *Peer) processIncomingHandshake(addr string, ephemPubBytes, nonce, ciphertext []byte, relayed bool, relayAddr string) ([]byte, string, error) {
	// Establish Tunnel
	curve := ecdh.X25519()
	ephemPub, err := curve.NewPublicKey(ephemPubBytes)
	if err != nil {
		return nil, "", err
	}

	tunnelSecret, err := p.EncPrivKey.ECDH(ephemPub)
	if err != nil {
		return nil, "", err
	}

	tunnelKey, err := cryptolib.DeriveSessionKey(tunnelSecret, []byte("Safem Handshake Tunnel"))
	if err != nil {
		return nil, "", err
	}

	tunnelAEAD, err := cryptolib.NewAEAD(tunnelKey)
	if err != nil {
		return nil, "", err
	}

	decrypted, err := tunnelAEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, "", fmt.Errorf("tunnel decryption failed: %v", err)
	}

	// Parse Identity & Key
	buf := bytes.NewReader(decrypted)
	var idLen uint16
	if err := binary.Read(buf, binary.BigEndian, &idLen); err != nil {
		return nil, "", err
	}

	idBytes := make([]byte, idLen)
	if _, err := buf.Read(idBytes); err != nil {
		return nil, "", err
	}
	senderID := string(idBytes)

	var pubKeyLen uint16
	if err := binary.Read(buf, binary.BigEndian, &pubKeyLen); err != nil {
		return nil, "", err
	}
	providedPubKey := make([]byte, pubKeyLen)
	if _, err := buf.Read(providedPubKey); err != nil {
		return nil, "", err
	}

	var ts uint64
	if err := binary.Read(buf, binary.BigEndian, &ts); err != nil {
		return nil, "", err
	}

	var sigLen uint16
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return nil, "", err
	}
	sig := make([]byte, sigLen)
	if _, err := buf.Read(sig); err != nil {
		return nil, "", err
	}

	// Check Timestamp
	now := time.Now().Unix()
	window := int64(HandshakeWindow.Seconds())
	if now-int64(ts) > window || int64(ts)-now > window {
		return nil, "", errors.New("handshake expired")
	}

	p.KeysMu.RLock()
	senderSignPub, ok := p.identities[senderID]
	p.KeysMu.RUnlock()

	if !ok {
		if len(providedPubKey) > 0 {
			if cryptolib.Fingerprint(ed25519.PublicKey(providedPubKey)) == senderID {
				senderSignPub = ed25519.PublicKey(providedPubKey)
			} else {
				return nil, "", fmt.Errorf("id mismatch for provided key")
			}
		} else {
			return nil, "", fmt.Errorf("unknown peer: %s", senderID)
		}
	}

	verifyData := fmt.Appendf(nil, "%s%d%x", senderID, ts, ephemPubBytes)
	if err := cryptolib.Verify(verifyData, sig, senderSignPub); err != nil {
		return nil, "", fmt.Errorf("invalid signature: %v", err)
	}

	// Check for Replay Cache
	sigHash := sha256.Sum256(sig)
	sigHashStr := hex.EncodeToString(sigHash[:])

	p.handshakeCacheMu.Lock()
	if seen, exists := p.handshakeCache[sigHashStr]; exists {
		if time.Since(seen) < HandshakeWindow {
			p.handshakeCacheMu.Unlock()
			return nil, "", fmt.Errorf("replay detected")
		}
	}

	// Enforce strict size limit on cache to prevent DoS (Memory Exhaustion)
	if len(p.handshakeCache) >= MaxHandshakeCacheSize {
		// Random eviction: since map iteration is random, deleting the first key
		// found effectively removes a random entry.
		for k := range p.handshakeCache {
			delete(p.handshakeCache, k)
			break
		}
	}

	p.handshakeCache[sigHashStr] = time.Now()
	p.handshakeCacheMu.Unlock()

	// Generate Session Keys
	respEphemPriv, respEphemPub, err := cryptolib.GenerateECDH()
	if err != nil {
		return nil, "", err
	}
	respEphemBytes := respEphemPub.Bytes()

	sessionSecret, err := respEphemPriv.ECDH(ephemPub)
	if err != nil {
		return nil, "", err
	}

	// Key for encrypting the response
	handshakeResKey, err := cryptolib.DeriveSessionKey(sessionSecret, []byte("Safem Handshake Resp"))
	if err != nil {
		return nil, "", err
	}

	handshakeAEAD, err := cryptolib.NewAEAD(handshakeResKey)
	if err != nil {
		return nil, "", err
	}

	// Construct Response
	myID := cryptolib.Fingerprint(p.PubKey)

	respSigData := []byte(fmt.Sprintf("%s%d%x%x", myID, now, ephemPubBytes, respEphemBytes))
	respSig, err := cryptolib.Sign(respSigData, p.PrivKey)
	if err != nil {
		return nil, "", err
	}

	respBuf := new(bytes.Buffer)
	binary.Write(respBuf, binary.BigEndian, uint16(len(myID)))
	respBuf.WriteString(myID)
	binary.Write(respBuf, binary.BigEndian, uint64(now))
	binary.Write(respBuf, binary.BigEndian, uint16(len(respSig)))
	respBuf.Write(respSig)

	respNonce, _ := cryptolib.GenerateRandomBytes(12)
	respCipher := handshakeAEAD.Seal(nil, respNonce, respBuf.Bytes(), nil)

	// Install Session with Double Ratchet Init
	rootKey, sendChainKey, recvChainKey, err := deriveChainKeys(sessionSecret, myID, senderID)
	if err != nil {
		return nil, "", err
	}

	wireID, err := deriveWireID(sessionSecret)
	if err != nil {
		return nil, "", err
	}

	name := p.GetName(senderID)

	p.KeysMu.Lock()
	if !relayed {
		p.peerIDs[addr] = senderID
	}
	p.KeysMu.Unlock()

	sRaw, _ := p.Sessions.LoadOrStore(senderID, &Session{
		ID:         senderID,
		Addr:       addr,
		Name:       name,
		LastRx:     time.Now(),
		LastRotate: time.Now(),
		WireID:     wireID,
	})
	s := sRaw.(*Session)

	s.Lock()
	s.Addr = addr
	s.RootKey = rootKey
	s.SendChainKey = sendChainKey
	s.RecvChainKey = recvChainKey
	s.InitRatchet(respEphemPriv, ephemPub)
	s.LastRx = time.Now()
	s.TxCount = 0
	s.RxCount = 0
	s.SkippedMessageKeys = make(map[uint64][]byte)

	s.IsRelayed = relayed
	s.RelayAddr = relayAddr

	s.Unlock()
	// Sealed Sender: register WireID
	p.WireIDSessions.Store(wireID, s)

	p.replayMu.Lock()
	delete(p.replayStates, senderID)
	p.replayMu.Unlock()

	mode := "Direct"
	if relayed {
		mode = "Relayed"
	}
	p.Logger("[Security] Accepted %s Handshake from %s. Secure WireID: %x\n", mode, name, wireID)

	out := make([]byte, 0, 32+12+len(respCipher))
	out = append(out, respEphemBytes...)
	out = append(out, respNonce...)
	out = append(out, respCipher...)

	return out, senderID, nil
}