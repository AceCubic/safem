package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/profile"
)

// InviteCall sends a call invitation to a user.
// If a call is already active, this acts as an "Add User" (conference) request.
func (c *Client) InviteCall(targetID string) error {
	sess, ok := c.Peer.GetSession(targetID)
	if !ok || sess.Addr == "" {
		return fmt.Errorf("peer offline")
	}

	isAdd := c.Voice.Active()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use Call instead of SendFast to ensure the invite is received (ACK/RINGING)
	_, err := c.Peer.Call(ctx, sess.Addr, protocol.OpCallInvite, []byte{})
	if err == nil {
		if isAdd {
			c.recordCallEvent(targetID, "Inviting to existing call...")
		} else {
			c.recordCallEvent(targetID, "Outgoing Call Invite")
		}
	}
	return err
}

// AnswerCall handles the user's decision to Accept or Reject an incoming call.
func (c *Client) AnswerCall(targetID string, accept bool) {
	sess, ok := c.Peer.GetSession(targetID)
	if !ok || sess.Addr == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if !accept {
		// Use Call to ensure rejection signal is delivered
		if _, err := c.Peer.Call(ctx, sess.Addr, protocol.OpCallReject, []byte{}); err != nil {
			c.Events.OnLog("Failed to deliver call rejection: %v\n", err)
		}
		c.recordCallEvent(targetID, "You rejected the call")
		return
	}

	// Accept: Send signal using Call to confirm connection establishment
	if _, err := c.Peer.Call(ctx, sess.Addr, protocol.OpCallAccept, []byte{}); err != nil {
		c.Events.OnLog("Failed to deliver call acceptance: %v\n", err)
		// We proceed anyway to try establishing audio, though handshake might fail if peer is gone
	}
	c.recordCallEvent(targetID, "You accepted the call")

	// Start Audio Engine
	name := c.Peer.GetName(targetID)
	if err := c.Voice.StartAddPeer(targetID); err != nil {
		c.Events.OnLog("Failed to start audio: %v\n", err)
	} else {
		c.Events.OnVoiceStatus(true, name)
	}
}

// ToggleMute switches the microphone mute state and returns the new state.
func (c *Client) ToggleMute() bool {
	return c.Voice.ToggleMute()
}

// HangupCall stops the audio engine and ends the current call session.
func (c *Client) HangupCall() {
	// Broadcast hangup signal to all active peers in the call
	// We need to access VoiceManager's map safely before stopping.
	c.Voice.mu.Lock()
	targets := make([]string, 0, len(c.Voice.ActivePeers))
	for _, addr := range c.Voice.ActivePeers {
		targets = append(targets, addr)
	}
	c.Voice.mu.Unlock()

	for _, addr := range targets {
		if addr != "" {
			// Send hangup signal to peer so they stop their engine
			go func(dest string) {
				c.Peer.SendFast(context.Background(), dest, protocol.OpCallHangup, []byte{})
			}(addr)
		}
	}

	c.Voice.StopAll()
	c.Events.OnVoiceStatus(false, "")
	c.recordCallEvent("System", "Call Ended")
}

// Handlers

// handleCallInvite processes an incoming OpCallInvite.
func (c *Client) handleCallInvite(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := c.Peer.GetID(remote.String())
	name := c.Peer.GetName(id)

	c.Events.OnIncomingCall(id, name)
	c.recordCallEvent(id, "Incoming Call")
	return []byte("RINGING"), nil
}

// handleCallAccept processes the peer's acceptance of our call.
func (c *Client) handleCallAccept(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := c.Peer.GetID(remote.String())
	name := c.Peer.GetName(id)

	c.recordCallEvent(id, fmt.Sprintf("Call accepted by %s", name))

	// Peer accepted, start our audio stream
	if err := c.Voice.StartAddPeer(id); err != nil {
		c.Events.OnLog("[Voice] Error starting engine: %v\n", err)
	} else {
		// Update Status
		targetName := name
		if c.Voice.GetTargetID() == "Group Call" {
			targetName = "Group Call"
		}
		c.Events.OnVoiceStatus(true, targetName)
	}
	// Return ACK so the other side's AnswerCall RPC completes successfully
	return []byte("ACK"), nil
}

// handleCallReject processes a call rejection.
func (c *Client) handleCallReject(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := c.Peer.GetID(remote.String())
	name := c.Peer.GetName(id)

	c.recordCallEvent(id, fmt.Sprintf("Call rejected by %s", name))
	// Return ACK so the other side's AnswerCall RPC completes
	return []byte("ACK"), nil
}

// handleCallHangup processes a hangup signal.
func (c *Client) handleCallHangup(remote *net.UDPAddr, data []byte) ([]byte, error) {
	id := c.Peer.GetID(remote.String())
	name := c.Peer.GetName(id)

	c.Voice.StopPeer(id)

	if c.Voice.Active() {
		c.Events.OnLog("[Voice] %s left the call.\n", name)
	} else {
		c.Events.OnVoiceStatus(false, "")
	}

	c.recordCallEvent(id, fmt.Sprintf("Call ended by %s", name))
	return nil, nil
}

// recordCallEvent logs system events to the chat history.
func (c *Client) recordCallEvent(id, text string) {
	c.Events.OnMessage(id, "System", text)
	c.Profile.AddMessage(id, profile.MessageEntry{
		Timestamp: time.Now().Unix(),
		SenderID:  "System",
		Content:   text,
	})
	go func() { c.Profile.Save() }()
}