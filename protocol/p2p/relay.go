package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	bstd "github.com/banditmoscow1337/benc/std/golang"
	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

// PerformRelayedHandshake attempts to establish a connection with a target peer via a Rendezvous Server.
// This is used as a fallback when direct P2P connection attempts (and hole punching) fail.
func (p *Peer) PerformRelayedHandshake(ctx context.Context, targetID, serverAddr string) error {
	// SingleFlight protection
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
	// [0][EphemPub][Nonce][Cipher] (No cookie support for relay initially)
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

	// Prepend 0 WireID for Cleartext
	finalInner := make([]byte, 4+len(marshaledInner))
	binary.BigEndian.PutUint32(finalInner[0:4], 0)
	copy(finalInner[4:], marshaledInner)

	// Wrap in OpRelay Payload: [TargetID][InnerPacket]
	// Use Benc for TargetID
	relayBuf := make([]byte, bstd.SizeString(targetID)+len(finalInner))
	n := bstd.MarshalString(0, relayBuf, targetID)
	copy(relayBuf[n:], finalInner)

	// Send OpRelay to Server & Wait for Response
	respCh := make(chan *protocol.Packet, 1)
	p.pendingMu.Lock()
	p.pending[reqID] = respCh
	p.pendingMu.Unlock()
	defer func() {
		p.pendingMu.Lock()
		delete(p.pending, reqID)
		p.pendingMu.Unlock()
	}()

	// Send to Server (Fire-and-forget, the response comes via pending)
	if err := p.SendFast(ctx, serverAddr, protocol.OpRelay, relayBuf); err != nil {
		return err
	}

	var respPayload []byte
	select {
	case resp := <-respCh:
		respPayload = resp.Payload
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return fmt.Errorf("relay handshake timeout")
	}

	// Process Response
	return p.finishHandshake(targetID, "", respPayload, ephemPriv, ephemPubBytes, targetSignPub, true, serverAddr)
}

// handleIncomingRelayedHandshake processes a handshake request forwarded via the relay.
func (p *Peer) handleIncomingRelayedHandshake(remote *net.UDPAddr, sourceID string, pkt protocol.Packet) ([]byte, error) {
	// Parse Payload
	data := pkt.Payload
	if len(data) < 1 {
		return nil, nil
	}
	// Relayed handshakes effectively skip the cookie phase for now, relying on server auth
	cookieLen := int(data[0])
	if len(data) < 1+cookieLen+32+12 {
		return nil, nil
	}

	ephemPubBytes := data[1+cookieLen : 1+cookieLen+32]
	nonce := data[1+cookieLen+32 : 1+cookieLen+32+12]
	ciphertext := data[1+cookieLen+32+12:]

	respPayload, err := p.processIncomingHandshake(remote.String(), ephemPubBytes, nonce, ciphertext, true, remote.String())
	if err != nil {
		p.Logger("[Relay] Handshake processing failed: %v\n", err)
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

	// Prepend WireID 0
	innerBuf := make([]byte, 4+len(marshaled))
	binary.BigEndian.PutUint32(innerBuf[0:4], 0)
	copy(innerBuf[4:], marshaled)

	// Wrap in OpRelay: [TargetID][InnerData]
	relayBuf := make([]byte, bstd.SizeString(sourceID)+len(innerBuf))
	n := bstd.MarshalString(0, relayBuf, sourceID)
	copy(relayBuf[n:], innerBuf)

	// Send OpRelay to Server
	p.SendFast(context.Background(), remote.String(), protocol.OpRelay, relayBuf)
	return nil, nil
}

// handleRelayedPacket unwraps a packet forwarded by the Rendezvous Server.
func (p *Peer) handleRelayedPacket(remote *net.UDPAddr, data []byte) ([]byte, error) {
	// Payload: [SourceID string][InnerData bytes]
	n, sourceID, err := bstd.UnmarshalString(0, data)
	if err != nil {
		return nil, err
	}
	innerData := data[n:]

	if len(innerData) < 4 {
		return nil, nil
	}

	// Peek WireID to determine if it's an encrypted session packet or a cleartext handshake
	wireID := binary.BigEndian.Uint32(innerData[0:4])

	if wireID != 0 {
		// Existing Encrypted Session
		// We explicitly look up the session by SourceID because the physical 'remote' address
		// is the Relay Server, not the peer.
		sess, ok := p.GetSession(sourceID)
		if !ok {
			return nil, nil
		}
		// Inject into standard packet processing
		p.transport.ProcessPacket(remote, sess, innerData)
		return nil, nil
	}

	// Cleartext (Handshake/Punch)
	pkt, err := protocol.UnmarshalPacket(innerData[4:])
	if err != nil {
		return nil, nil
	}

	if pkt.Op == protocol.OpHandshake {
		// Handshake Response (Initiator Logic)
		// If it's a reply to OUR handshake request, dispatch it to the waiting goroutine via 'pending'.
		if pkt.IsReply {
			p.dispatchPacket(remote, nil, 0, pkt)
			return nil, nil
		}

		// Handshake Request (Responder Logic)
		// Someone is trying to connect to us via the Relay.
		// We handle this with a specialized handler that knows to reply via the Relay.
		return p.handleIncomingRelayedHandshake(remote, sourceID, pkt)
	}

	return nil, nil
}