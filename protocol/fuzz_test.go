package protocol

import (
	"bytes"
	"testing"
)

// FuzzUnmarshalPacket verifies that random input does not crash the parser
// and that successfully parsed packets maintain integrity when re-marshaled.
func FuzzUnmarshalPacket(f *testing.F) {
	// Seed corpus
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // Empty packet structure

	f.Fuzz(func(t *testing.T, data []byte) {
		// Attempt to Unmarshal
		pkt, err := UnmarshalPacket(data)
		if err != nil {
			// Expected error for garbage data
			return
		}

		// Sanity Checks on Parsed Data
		// The payload and padding should be slices of the original data (Zero-Copy)
		// We can't strictly assert cap/len bounds generically, but we can check nil safety.
		if pkt.Payload == nil && len(pkt.Payload) > 0 {
			t.Error("Payload is nil but len > 0")
		}

		// Round-Trip Verification
		// If the packet was valid, Marshaling it back should succeed.
		// Note: MarshalPacket adds padding to reach TargetWireSize.
		// Therefore, 'marshaled' might not equal 'data' exactly (due to padding differences),
		// but Unmarshal(marshaled) must yield the same struct 'pkt'.

		marshaled := MarshalPacket(pkt)
		
		// Unmarshal the re-marshaled bytes
		pkt2, err2 := UnmarshalPacket(marshaled)
		if err2 != nil {
			t.Fatalf("Round-trip failed: could not unmarshal re-marshaled packet: %v", err2)
		}

		// Compare Fields
		if pkt.ReqID != pkt2.ReqID {
			t.Errorf("ReqID mismatch: %d != %d", pkt.ReqID, pkt2.ReqID)
		}
		if pkt.SequenceID != pkt2.SequenceID {
			t.Errorf("SequenceID mismatch: %d != %d", pkt.SequenceID, pkt2.SequenceID)
		}
		if pkt.Op != pkt2.Op {
			t.Errorf("Op mismatch: %v != %v", pkt.Op, pkt2.Op)
		}
		if pkt.IsReply != pkt2.IsReply {
			t.Errorf("IsReply mismatch: %v != %v", pkt.IsReply, pkt2.IsReply)
		}

		// Compare Payload Content
		if !bytes.Equal(pkt.Payload, pkt2.Payload) {
			t.Error("Payload content mismatch after round-trip")
		}
		
		// Clean up pool usage implicitly (MarshalPacket uses packetPool)
		// In a real app, we would FreePacketBuffer(marshaled), but for fuzzing/testing 
		// with the provided code, checking for leaks is hard without explicit hooks.
		FreePacketBuffer(marshaled)
	})
}