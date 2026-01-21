package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/profile"
)

// SendText sends a secured, signed text message to a specific peer.
// It persists the message to the local profile history and attempts to deliver it immediately.
// If the peer is offline, the message is queued for store-and-forward delivery.
func (c *Client) SendText(ctx context.Context, targetID, text string) error {
	sig, err := cryptolib.Sign([]byte(text), c.Peer.PrivKey)
	if err != nil {
		return fmt.Errorf("failed to sign message: %v", err)
	}

	entry := profile.MessageEntry{
		Timestamp: time.Now().Unix(),
		SenderID:  c.Profile.GetID(),
		Signature: sig,
		Content:   text,
	}

	c.Profile.AddMessage(targetID, entry)

	go func() {
		if err := c.Profile.Save(); err != nil {
			c.Events.OnLog("[System] Failed to save history: %v\n", err)
		}
	}()

	sess, ok := c.Peer.GetSession(targetID)
	online := ok && sess.Addr != ""

	if !online {
		c.Profile.AddPending(targetID, entry)
		go c.Profile.Save()
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(sig)))
	buf.Write(sig)
	buf.WriteString(text)

	if err := c.Peer.SendLarge(ctx, sess.Addr, protocol.OpMsg, buf.Bytes()); err != nil {
		c.Profile.AddPending(targetID, entry)
		go c.Profile.Save()
		return nil 
	}

	return nil
}

// handleMsg processes an incoming text message.
func (c *Client) handleMsg(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := c.Peer.GetID(remote.String())

	if len(data) < 2 {
		return nil, fmt.Errorf("msg too short")
	}
	sigLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 2+int(sigLen) {
		return nil, fmt.Errorf("msg malformed")
	}
	
	// 'data' is backed by the transient network buffer.
	// We MUST copy the signature because it is stored in the Profile's persistent history.
	sig := make([]byte, sigLen)
	copy(sig, data[2 : 2+sigLen])
	
	text := string(data[2+sigLen:])

	var pub ed25519.PublicKey

	if f, ok := c.Profile.GetFriend(id); ok {
		pub, _ = cryptolib.PEMToPubKey([]byte(f.PEM))
	} else {
		if p, ok := c.Peer.GetIdentity(id); ok {
			pub = p
		}
	}

	if pub != nil {
		if err := cryptolib.Verify([]byte(text), sig, pub); err != nil {
			c.Events.OnLog("[Security] Signature verification failed for message from %s\n", id)
		} else {
			c.Profile.AddMessage(id, profile.MessageEntry{
				Timestamp: time.Now().Unix(),
				SenderID:  id,
				Signature: sig,
				Content:   text,
			})
			go c.Profile.Save()
		}
	} else {
		c.Events.OnLog("[Security] Cannot verify message from %s (No Public Key found)\n", id)
	}

	name := c.Peer.GetName(id)
	c.Events.OnMessage(id, name, text)
	return protocol.PackStrings("ACK"), nil
}

// SendTyping transmits a typing indicator notification to the specified target peer.
// It allows the remote user to see that a message is being composed.
func (c *Client) SendTyping(ctx context.Context, targetID string) error {
	sess, ok := c.Peer.GetSession(targetID)
	if !ok || sess.Addr == "" {
		return fmt.Errorf("peer offline")
	}
	return c.Peer.SendFast(ctx, sess.Addr, protocol.OpTyping, []byte{})
}