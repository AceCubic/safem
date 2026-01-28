package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	bstd "github.com/banditmoscow1337/benc/std/golang"
	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

// PerformRelayedHandshake attempts to establish a connection with a target peer via a Rendezvous Server.
func (p *Peer) PerformRelayedHandshake(ctx context.Context, targetID, serverAddr string) error {
	p.handshakeInFlightMu.Lock()
	key := "relay:" + targetID
	if ch, ok := p.handshakeInFlight[key]; ok {
		p.handshakeInFlightMu.Unlock()
		select {
		case <-ch:
			if _, ok := p.GetSession(targetID); ok {
				return nil
			}
			return errors.New("concurrent relay handshake failed")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ch := make(chan struct{})
	p.handshakeInFlight[key] = ch
	p.handshakeInFlightMu.Unlock()
	defer func() {
		p.handshakeInFlightMu.Lock()
		delete(p.handshakeInFlight, key)
		p.handshakeInFlightMu.Unlock()
		close(ch)
	}()

	p.KeysMu.RLock()
	targetEncPub := p.encIdentities[targetID]
	targetSignPub := p.identities[targetID]
	p.KeysMu.RUnlock()

	if targetEncPub == nil || targetSignPub == nil {
		return errors.New("cannot handshake: peer keys unknown")
	}

	// Retrieve Write Token (Authorization to send via Relay)
	writeToken, ok := p.GetWriteToken(targetID)
	if !ok {
		return errors.New("no write token for sealed sender routing (OpQuery needed)")
	}

	// Generate Ephemeral Key
	ephemPriv, ephemPub, err := cryptolib.GenerateECDH()
	if err != nil {
		return err
	}
	ephemPubBytes := ephemPub.Bytes()

	// Establish Encrypted Tunnel (E_init * S_resp)
	tunnelSecret, err := ephemPriv.ECDH(targetEncPub)
	if err != nil {
		return err
	}

	tunnelKey, err := cryptolib.DeriveSessionKey(tunnelSecret, []byte("Safem Handshake Tunnel"))
	if err != nil {
		return err
	}

	// Prepare Secured Payload
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

	// Construct Inner Handshake Packet (Cleartext logic, WireID=0)
	buf := new(bytes.Buffer)
	buf.WriteByte(0) // No cookie
	buf.Write(ephemPubBytes)
	buf.Write(nonce)
	buf.Write(ciphertext)

	reqID := atomic.AddUint64(&p.reqIDSeq, 1)

	innerPacket := protocol.Packet{
		ReqID:      reqID,
		SequenceID: 0,
		Op:         protocol.OpHandshake,
		Payload:    buf.Bytes(),
	}

	marshaledInner := protocol.MarshalPacket(innerPacket)

	// Prepend 0 WireID for Cleartext using 8 bytes (uint64)
	finalInner := make([]byte, 8+len(marshaledInner))
	binary.BigEndian.PutUint64(finalInner[0:8], 0)
	copy(finalInner[8:], marshaledInner)

	// Wrap in OpRelay Payload: [WriteToken][InnerPacket]
	relayBuf := make([]byte, bstd.SizeString(writeToken)+len(finalInner))
	n := bstd.MarshalString(0, relayBuf, writeToken)
	copy(relayBuf[n:], finalInner)

	// Send OpRelay to Server & Wait for Response
	if err := p.SendFast(ctx, serverAddr, protocol.OpRelay, relayBuf); err != nil {
		return err
	}

	// Wait for Session to appear (handled by Poller -> handleRelayedPacket -> finishHandshake)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(15 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("relay handshake timeout (poller did not retrieve response)")
		case <-ticker.C:
			if _, ok := p.GetSession(targetID); ok {
				return nil
			}
		}
	}
}

// StartPIR starts the background poller for fetching relayed messages.
// This implements a bucket-based PIR where we request a shared bucket based on our Read Token (SubID).
func (p *Peer) StartPIR(ctx context.Context, serverAddr, myReadToken string) {
	if len(myReadToken) < 2 {
		p.Logger("[PIR] Invalid Read Token, cannot start poller")
		return
	}

	// Store Relay Address in Peer for outbound responses
	p.SetRelayServer(serverAddr)

	// Derive Bucket Index from Read Token (first byte of hex)
	bucketIdx, err := strconv.ParseUint(myReadToken[0:2], 16, 8)
	if err != nil {
		p.Logger("[PIR] Failed to derive bucket: %v", err)
		return
	}

	ticker := time.NewTicker(2 * time.Second) // Poll every 2s
	defer ticker.Stop()

	p.Logger("[PIR] Starting Poller for Bucket %d (Token: %s...)", bucketIdx, myReadToken[:8])

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send OpPIRQuery: [BucketIndex]
			req := make([]byte, 1)
			req[0] = byte(bucketIdx)

			// We use Call to get the response immediately
			resp, err := p.Call(ctx, serverAddr, protocol.OpPIRQuery, req)
			if err != nil {
				continue
			}

			// Unpack Messages: [Count][Len][Data][Len][Data]...
			// The response is a slice of byte slices.
			var messages [][]byte
			_, messages, err = bstd.UnmarshalSlice[[]byte](0, resp, func(n int, b []byte, v *[]byte) (int, []byte, error) {
				return bstd.UnmarshalBytesCopied(n, b)
			})

			if err != nil {
				p.Logger("[PIR] Malformed response: %v", err)
				continue
			}

			// Process each message found in the bucket
			for _, msg := range messages {
				// We don't know who the sender is or if it's for us.
				// handleRelayedPacket checks WireID or tries to handshake decrypt.
				p.handleRelayedPacket(nil, msg)
			}
		}
	}
}


// handleIncomingRelayedHandshake processes a handshake request forwarded via the relay.
func (p *Peer) handleIncomingRelayedHandshake(remote *net.UDPAddr, pkt protocol.Packet) ([]byte, error) {
	data := pkt.Payload
	if len(data) < 1 {
		return nil, nil
	}
	cookieLen := int(data[0])
	if len(data) < 1+cookieLen+32+12 {
		return nil, nil
	}

	ephemPubBytes := data[1+cookieLen : 1+cookieLen+32]
	nonce := data[1+cookieLen+32 : 1+cookieLen+32+12]
	ciphertext := data[1+cookieLen+32+12:]

	// Sealed Sender: We extract the sender ID from the internal encrypted payload
	// Since we are polling, 'remote' is nil or the server. processIncomingHandshake handles logic.
	respPayload, sourceID, err := p.processIncomingHandshake("RELAY", ephemPubBytes, nonce, ciphertext, true, "RELAY")
	if err != nil {
		// Decryption failure is expected for messages in the bucket not meant for us
		return nil, nil
	}

	// Construct Response Packet
	respPkt := protocol.Packet{
		ReqID:      pkt.ReqID, // Match request ID for IsReply logic
		SequenceID: 0,
		IsReply:    true,
		Op:         protocol.OpHandshake,
		Payload:    respPayload,
	}

	marshaled := protocol.MarshalPacket(respPkt)

	// Prepend WireID 0 using 8 bytes (uint64)
	innerBuf := make([]byte, 8+len(marshaled))
	binary.BigEndian.PutUint64(innerBuf[0:8], 0)
	copy(innerBuf[8:], marshaled)

	// To Reply, we need the Initiator's WriteToken.
	// We might have it if we queried them before.
	writeToken, ok := p.GetWriteToken(sourceID)
	if !ok {
		// Limitation: In this basic PIR/Relay impl, if we don't have the token, we can't reply via relay.
		// The initiator should ideally include their WriteToken in the encrypted payload, or we must query server.
		p.Logger("[Relay] Cannot reply to handshake: missing Write Token for %s\n", sourceID)
		return nil, nil
	}

	// Wrap in OpRelay: [WriteToken][InnerData]
	relayBuf := make([]byte, bstd.SizeString(writeToken)+len(innerBuf))
	n := bstd.MarshalString(0, relayBuf, writeToken)
	copy(relayBuf[n:], innerBuf)

	// Send OpRelay to Server (Push)
	p.KeysMu.RLock()
	serverAddr := p.RelayServerAddr
	p.KeysMu.RUnlock()

	if serverAddr == "" {
		p.Logger("[Relay] Cannot reply to handshake: RelayServerAddr not set (StartPIR not running?)")
		return nil, nil
	}

	// Fire-and-forget the response to the relay server
	if err := p.SendFast(context.TODO(), serverAddr, protocol.OpRelay, relayBuf); err != nil {
		p.Logger("[Relay] Failed to push handshake response: %v\n", err)
	}

	return nil, nil
}

// handleRelayedPacket unwraps a packet retrieved from the PIR bucket.
// It determines if the packet belongs to this user by checking WireID or attempting Handshake decryption.
func (p *Peer) handleRelayedPacket(remote *net.UDPAddr, data []byte) ([]byte, error) {
	// data is [WireID][Packet]
	
	if len(data) < 8 {
		return nil, nil
	}

	wireID := binary.BigEndian.Uint64(data[0:8])

	if wireID != 0 {
		// Existing Encrypted Session
		// We must look up the session by WireID.
		sess, ok := p.GetSessionByWireID(wireID)
		if !ok {
			// WireID mismatch means this packet is for someone else in the bucket.
			return nil, nil
		}
		
		// Found session, process it.
		// We pass 'sess' to bypass IP check in Transport.
		// 'remote' is irrelevant for relayed packets.
		p.transport.ProcessPacket(nil, sess, data)
		return nil, nil
	}

	// Cleartext (Handshake)
	// Try to unmarshal.
	pkt, err := protocol.UnmarshalPacket(data[8:])
	if err != nil {
		return nil, nil
	}

	if pkt.Op == protocol.OpHandshake {
		// Handshake Response
		if pkt.IsReply {
			p.dispatchPacket(nil, nil, 0, pkt)
			return nil, nil
		}

		// Handshake Request
		return p.handleIncomingRelayedHandshake(remote, pkt)
	}

	return nil, nil
}