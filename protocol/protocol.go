package protocol

import (
	"sync"

	bstd "github.com/banditmoscow1337/benc/std/golang"
)

type OpCode uint8

const (
	OpReserved        OpCode = 0x00
	OpRegister        OpCode = 0x01
	OpInvite          OpCode = 0x02
	OpAcceptInvite    OpCode = 0x03
	OpIncomingInvite  OpCode = 0x04
	OpInviteFinalized OpCode = 0x05
	OpMsg             OpCode = 0x06
	OpVoice           OpCode = 0x07 // Audio Data
	OpDisconnect      OpCode = 0x08
	OpHandshake       OpCode = 0x09
	OpPing            OpCode = 0x0A
	OpChunk           OpCode = 0x0B
	OpHandshakeAck    OpCode = 0x0C
	OpFile            OpCode = 0x0E // Legacy/Single-shot (RAM)
	OpPunch           OpCode = 0xFF
	OpHeartbeat       OpCode = 0x0F
	OpFileStart       OpCode = 0x10
	OpFileBlock       OpCode = 0x11
	OpCallInvite      OpCode = 0x12
	OpCallAccept      OpCode = 0x13
	OpCallReject      OpCode = 0x14
	OpCallHangup      OpCode = 0x15
	OpTyping          OpCode = 0x17
	OpFileAccept      OpCode = 0x18
	OpFileReject      OpCode = 0x19
	
	// Group Chat Operations
	OpGroupInvite     OpCode = 0x20
	OpGroupMsg        OpCode = 0x21
	OpGroupLeave      OpCode = 0x22
	OpGroupKick       OpCode = 0x23

	// Group Consistency / Sync
	OpGroupSyncReq    OpCode = 0x26
	OpGroupSyncRes    OpCode = 0x27

	// User Content Sync
	OpUserUpdate      OpCode = 0x24

	// Discovery
	OpQuery           OpCode = 0x25

	// Relay
	OpRelay           OpCode = 0x28

	// PIR (Private Information Retrieval) for Relay
	OpPIRQuery        OpCode = 0x29
	OpPIRResponse     OpCode = 0x30

	// Security / Audit
	OpRootBroadcast   OpCode = 0x2A // Gossip latest Server Root Hash to detect Split View
)

const (
	// HeaderSize is deprecated as Benc uses variable length encoding.
	HeaderSize = 20
	
	// TargetWireSize is the constant size for all packets on the wire to prevent fingerprinting.
	TargetWireSize = 1280

	// ChunkSize is reduced to leave room for Headers + Encryption Overhead + Padding
	ChunkSize  = 1000

	// MaxPacketSize is the maximum size of a packet on the wire.
	MaxPacketSize = 65535
)

// sync.Pool to reuse packet buffers and reduce GC pressure
var packetPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, MaxPacketSize)
	},
}

// Global zero buffer for padding to avoid allocations during MarshalPacket.
var zeroPadding = make([]byte, TargetWireSize)

// GetPacketBuffer retrieves a byte slice from the pool.
func GetPacketBuffer() []byte {
	return packetPool.Get().([]byte)
}

// FreePacketBuffer returns a buffer to the pool.
func FreePacketBuffer(b []byte) {
	if cap(b) >= MaxPacketSize {
		packetPool.Put(b)
	}
}

type Packet struct {
	ReqID      uint64
	SequenceID uint64
	IsReply    bool
	Op         OpCode
	Payload    []byte
	Padding    []byte 
}

func MarshalPacket(p Packet) []byte {
	// Calculate Base Size (without Padding)
	// We temporarily treat Padding as nil to calculate the intrinsic size of the packet.
	p.Padding = nil

	s := 0
	s += bstd.SizeUint64() // ReqID
	s += bstd.SizeUint64() // SequenceID
	s += bstd.SizeBool()   // IsReply
	s += bstd.SizeByte()   // Op
	s += bstd.SizeBytes(p.Payload)

	// Add overhead for an empty/nil padding field (usually 1 byte for length prefix 0)
	baseSize := s + bstd.SizeBytes(nil)

	// Calculate Padding
	// If the packet is smaller than the TargetWireSize, we pad it.
	if baseSize < TargetWireSize {
		// Bytes remaining to reach target
		needed := TargetWireSize - baseSize
		
		// The serialized size of the padding field = LenPrefix + Content.
		// We need to find 'padLen' such that SizeBytes(padLen) == needed.
		
		// Heuristic: Most varint prefixes are 1 byte for lengths < 128.
		// If needed is 100, padLen = 99. SizeBytes(99) = 1 + 99 = 100.
		// If needed is 200, prefix might be 2 bytes. padLen = 198. SizeBytes(198) = 2 + 198 = 200.
		
		// Start with assumption of 1 byte overhead
		padLen := needed - 1
		
		// Check if that assumption holds (i.e., does this length cause a 2-byte prefix?)
		// We slice zeroPadding just to check the size calculation.
		if padLen > 0 {
			if padLen > len(zeroPadding) {
				padLen = len(zeroPadding)
			}
			
			checkSize := bstd.SizeBytes(zeroPadding[:padLen])
			if checkSize > needed {
				// Overhead was larger than 1 (likely 2). Reduce data by 1 to accommodate.
				padLen--
			}
			
			// Apply padding
			if padLen > 0 {
				p.Padding = zeroPadding[:padLen]
			}
		}
	}

	// Final Size Calculation and Marshal
	s = 0
	s += bstd.SizeUint64() // ReqID
	s += bstd.SizeUint64() // SequenceID
	s += bstd.SizeBool()   // IsReply
	s += bstd.SizeByte()   // Op
	s += bstd.SizeBytes(p.Payload)
	s += bstd.SizeBytes(p.Padding)

	buf := packetPool.Get().([]byte)
	
	if cap(buf) < s {
		buf = make([]byte, 0, s)
	}
	buf = buf[:s]

	n := bstd.MarshalUint64(0, buf, p.ReqID)
	n = bstd.MarshalUint64(n, buf, p.SequenceID)
	n = bstd.MarshalBool(n, buf, p.IsReply)
	n = bstd.MarshalByte(n, buf, uint8(p.Op))
	n = bstd.MarshalBytes(n, buf, p.Payload)
	n = bstd.MarshalBytes(n, buf, p.Padding)

	return buf
}

func UnmarshalPacket(data []byte) (Packet, error) {
	var p Packet
	var err error
	n := 0

	if n, p.ReqID, err = bstd.UnmarshalUint64(n, data); err != nil {
		return Packet{}, err
	}

	if n, p.SequenceID, err = bstd.UnmarshalUint64(n, data); err != nil {
		return Packet{}, err
	}

	if n, p.IsReply, err = bstd.UnmarshalBool(n, data); err != nil {
		return Packet{}, err
	}

	var opVal uint8
	if n, opVal, err = bstd.UnmarshalByte(n, data); err != nil {
		return Packet{}, err
	}
	p.Op = OpCode(opVal)

	// We use UnmarshalBytes instead of UnmarshalBytesCopied.
	// This makes p.Payload a slice of 'data', avoiding an allocation/copy.
	// WARNING: The payload is only valid as long as the underlying 'data' buffer is valid.
	if n, p.Payload, err = bstd.UnmarshalBytesCropped(n, data); err != nil {
		return Packet{}, err
	}

	// Unmarshal padding
	if n, p.Padding, err = bstd.UnmarshalBytesCropped(n, data); err != nil {
		return Packet{}, err
	}

	return p, nil
}

func PackStrings(strs ...string) []byte {
    // Calculate size
    size := bstd.SizeSlice(strs, bstd.SizeString)

    // Get from pool
    buf := packetPool.Get().([]byte)
    if cap(buf) < size {
        buf = make([]byte, 0, size) // Fallback if pool slice too small
    }
    buf = buf[:size]

    // Marshal
    bstd.MarshalSlice(0, buf, strs, bstd.MarshalString)
    return buf
}

func UnpackStrings(data []byte) (res []string) {
	if len(data) == 0 {
		return
	}
	_, res, _ = bstd.UnmarshalSlice[string](0, data, bstd.UnmarshalString)
	return
}