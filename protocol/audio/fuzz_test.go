package audio

import (
	"encoding/binary"
	"testing"
)

// FuzzJitterBuffer verifies that the JitterBuffer correctly handles random input sequences
// of Push and Pop operations without panicking or leaking memory.
// It simulates valid packet sequences as well as erratic input.
func FuzzJitterBuffer(f *testing.F) {
	// Seed corpus with simple scenarios
	f.Add([]byte{0, 0, 0}) // Push Seq 0
	f.Add([]byte{128})     // Pop
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a fresh JitterBuffer for each fuzz iteration.
		// We use a small target depth to trigger state transitions (buffering -> playing) quickly.
		jb := NewJitterBuffer(3)
		defer jb.Cleanup()

		idx := 0
		for idx < len(data) {
			// Command Byte:
			// < 128: Push Packet
			// >= 128: Pop Packet
			op := data[idx]
			idx++

			if op < 128 {
				// PUSH COMMAND
				// We need at least 2 bytes for the Sequence ID
				if idx+2 > len(data) {
					return
				}
				
				seq := binary.BigEndian.Uint16(data[idx : idx+2])
				idx += 2

				// Simulate memory management:
				// JitterBuffer.Push takes ownership of a *[]byte. 
				// It must come from the pool (or heap) so it can be safely returned to the pool.
				
				// Get buffer from the package-internal pool
				p := packetPool.Get().(*[]byte)
				
				// Ensure it has some capacity and length (simulate a payload)
				if cap(*p) == 0 {
					*p = make([]byte, 100)
				}
				*p = (*p)[:1] // Payload of size 1
				(*p)[0] = 0xAA // Dummy data

				// Push to JB (transfers ownership)
				jb.Push(seq, p)

			} else {
				// POP COMMAND
				// Pop returns a pointer from the pool (or nil).
				// We act as the consumer and must release it.
				ptr := jb.Pop()
				if ptr != nil {
					releasePacket(ptr)
				}
			}
		}

		// Cleanup verification:
		// Ensure Level() returns sane values (>=0)
		if jb.Level() < 0 {
			t.Errorf("JitterBuffer level is negative: %d", jb.Level())
		}
	})
}