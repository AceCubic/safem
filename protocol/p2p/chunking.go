package p2p

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

const (
	// MaxConcurrentChunks limits the number of active incoming file transfers
	// to prevent memory exhaustion or disk spamming.
	MaxConcurrentChunks = 32

	// MaxChunksPerPeer limits the number of active transfers allowed from a single peer.
	MaxChunksPerPeer = 3

	// MaxPayloadSize defines the maximum allowed size for a reassembled message or file.
	// 50 MB limits the temporary disk space usage per transfer.
	MaxPayloadSize = 50 * 1024 * 1024
)

// ChunkBuffer manages the reassembly of a large message split into multiple packets.
type ChunkBuffer struct {
	sync.Mutex
	SenderID   string
	Chunks     map[uint16][]byte
	Total      uint16
	Received   uint16
	File       *os.File
	FilePath   string
	SeenChunks []uint64
	OriginalOp protocol.OpCode
	LastUpdate time.Time
}

// SendLarge splits a large payload into chunks and sends them reliably to the target.
// It uses a sliding window protocol with congestion control to manage flow and retransmissions.
func (p *Peer) SendLarge(ctx context.Context, targetAddr string, op protocol.OpCode, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return fmt.Errorf("payload too large (max %d bytes)", MaxPayloadSize)
	}

	if len(payload) <= protocol.ChunkSize {
		_, err := p.Call(ctx, targetAddr, op, payload)
		return err
	}

	totalLen := len(payload)
	chunkSize := protocol.ChunkSize
	totalChunks := int((totalLen + chunkSize - 1) / chunkSize)

	idBytes, _ := cryptolib.GenerateRandomBytes(8)
	transferID := binary.BigEndian.Uint64(idBytes)

	const (
		TargetDelay = 100 * time.Millisecond
		Gain        = 1.0
		InitWindow  = 4.0
		MaxWindow   = 100.0
		MinWindow   = 1.0
		Workers     = 4
		RTO         = 500 * time.Millisecond
	)

	var (
		cwnd       = InitWindow
		baseRTT    = time.Hour
		flightSize = 0
	)

	ackChan := make(chan *protocol.Packet, 128)

	type sendJob struct {
		seq   int
		reqID uint64
		data  []byte
	}

	sendQueue := make(chan sendJob, int(MaxWindow))
	errChan := make(chan error, 1)

	var wg sync.WaitGroup
	ctxWorkers, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	defer func() {
		cancelWorkers()
		close(sendQueue)
		wg.Wait()
	}()

	for range Workers {
		wg.Go(func() {
			for job := range sendQueue {
				if ctxWorkers.Err() != nil {
					return
				}

				// Get a recycled buffer from the pool
				buf := protocol.GetPacketBuffer()

				// Append header manually (faster than binary.Write)
				// Need ~13 bytes for header + len(job.data)
				// Ensure capacity or handle appropriately, typically MaxPacketSize is enough

				// Reset length to 0 but keep capacity
				buf = buf[:0]

				// Append Header (TransferID 8, Seq 2, Total 2, Op 1)
				buf = binary.BigEndian.AppendUint64(buf, transferID)
				buf = binary.BigEndian.AppendUint16(buf, uint16(job.seq))
				buf = binary.BigEndian.AppendUint16(buf, uint16(totalChunks))
				buf = append(buf, byte(op))

				// Append Data
				buf = append(buf, job.data...)

				pkt := protocol.Packet{
					ReqID:      job.reqID,
					SequenceID: atomic.AddUint64(&p.sendSeq, 1),
					Op:         protocol.OpChunk,
					Payload:    buf, // Pass the pooled buffer
				}

				if err := p.sendPacket(targetAddr, pkt); err != nil {
					select {
					case errChan <- err:
					default:
					}
				}

				// sendPacket marshals the packet, which COPIES the payload.
				// So we can safely return 'buf' to the pool immediately.
				protocol.FreePacketBuffer(buf)
			}
		})
	}

	acked := make([]bool, totalChunks)
	sentTime := make([]time.Time, totalChunks)

	chunkReqIDs := make(map[int]uint64)
	reqToChunk := make(map[uint64]int)

	windowStart := 0
	ackedCount := 0

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	removePending := func(reqID uint64) {
		p.pendingMu.Lock()
		delete(p.pending, reqID)
		p.pendingMu.Unlock()
	}

	for ackedCount < totalChunks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errChan:
			return err
		case pkt := <-ackChan:
			if seq, ok := reqToChunk[pkt.ReqID]; ok {
				now := time.Now()
				rtt := now.Sub(sentTime[seq])

				if rtt < baseRTT {
					baseRTT = rtt
				}

				queuingDelay := max(rtt - baseRTT, 0)

				offTarget := float64(TargetDelay-queuingDelay) / float64(TargetDelay)

				if cwnd > 0 {
					cwnd += (Gain * offTarget) / cwnd
				}

				if cwnd < MinWindow {
					cwnd = MinWindow
				}
				if cwnd > MaxWindow {
					cwnd = MaxWindow
				}

				removePending(pkt.ReqID)
				delete(reqToChunk, pkt.ReqID)

				if !acked[seq] {
					acked[seq] = true
					ackedCount++
					flightSize--
				}

				for windowStart < totalChunks && acked[windowStart] {
					windowStart++
				}
			}

		case <-ticker.C:
			intCwnd := max(int(cwnd), 1)

			limit := min(windowStart + intCwnd, totalChunks)

			for i := windowStart; i < limit; i++ {
				if flightSize >= intCwnd {
					break
				}

				if acked[i] {
					continue
				}

				if sentTime[i].IsZero() || time.Since(sentTime[i]) > RTO {
					if !sentTime[i].IsZero() {
						// This is a Retransmission
						p.Retransmits.Add(1)

						cwnd = cwnd * 0.5
						if cwnd < MinWindow {
							cwnd = MinWindow
						}

						if oldReqID, exists := chunkReqIDs[i]; exists {
							removePending(oldReqID)
							delete(reqToChunk, oldReqID)
							flightSize--
						}
					}

					reqID := atomic.AddUint64(&p.reqIDSeq, 1)

					p.pendingMu.Lock()
					p.pending[reqID] = ackChan
					p.pendingMu.Unlock()

					sentTime[i] = time.Now()
					chunkReqIDs[i] = reqID
					reqToChunk[reqID] = i
					flightSize++

					start := i * chunkSize
					end := min(start + chunkSize, totalLen)

					select {
					case sendQueue <- sendJob{seq: i, reqID: reqID, data: payload[start:end]}:
					default:
					}
				}
			}
		}
	}

	return nil
}

func (p *Peer) handleChunk(remote *net.UDPAddr, data []byte) ([]byte, error) {
	sess, ok := p.GetSessionByAddr(remote.String())
	if !ok || sess.Addr == "" {
		p.PacketsDropped.Add(1)
		return nil, errors.New("chunks rejected: sender is not in an active session")
	}
	senderID := sess.ID

	if len(data) < 13 {
		p.PacketsDropped.Add(1)
		return nil, errors.New("chunk too short")
	}

	transferID := binary.BigEndian.Uint64(data[0:8])
	seq := binary.BigEndian.Uint16(data[8:10])
	total := binary.BigEndian.Uint16(data[10:12])
	origOp := protocol.OpCode(data[12])
	chunkData := data[13:]

	if len(chunkData) > protocol.ChunkSize {
		p.PacketsDropped.Add(1)
		return nil, fmt.Errorf("chunk data exceeds maximum size")
	}

	if uint64(total)*uint64(protocol.ChunkSize) > MaxPayloadSize {
		p.PacketsDropped.Add(1)
		return nil, errors.New("transfer exceeds maximum allowed payload size")
	}

	p.chunkMu.Lock()
	buf, exists := p.chunkBuffers[transferID]

	if exists {
		if buf.SenderID != senderID {
			p.chunkMu.Unlock()
			p.PacketsDropped.Add(1)
			return nil, fmt.Errorf("chunk rejected: transfer ID mismatch (hijack attempt)")
		}
	} else {
		if len(p.chunkBuffers) >= MaxConcurrentChunks {
			p.pruneStaleChunks()
			if len(p.chunkBuffers) >= MaxConcurrentChunks {
				p.chunkMu.Unlock()
				p.PoolStarvation.Add(1)
				return nil, errors.New("too many active chunk transfers (global limit)")
			}
		}

		peerCount := 0
		for _, b := range p.chunkBuffers {
			if b.SenderID == senderID {
				peerCount++
			}
		}
		if peerCount >= MaxChunksPerPeer {
			p.chunkMu.Unlock()
			p.PoolStarvation.Add(1)
			return nil, fmt.Errorf("too many active transfers for this peer (limit %d)", MaxChunksPerPeer)
		}

		buf = &ChunkBuffer{
			SenderID:   senderID,
			Chunks:     make(map[uint16][]byte),
			Total:      total,
			OriginalOp: origOp,
			LastUpdate: time.Now(),
		}

		if origOp == protocol.OpFile {
			f, err := os.CreateTemp("", "chat_chunk_*")
			if err == nil {
				buf.File = f
				buf.FilePath = f.Name()
				nWords := (int(total) + 63) / 64
				buf.SeenChunks = make([]uint64, nWords)
			} else {
				fmt.Printf("Failed to create temp file for chunking: %v\n", err)
			}
		}

		p.chunkBuffers[transferID] = buf
	}
	p.chunkMu.Unlock()

	buf.Lock()
	defer buf.Unlock()

	if seq >= buf.Total {
		return nil, fmt.Errorf("sequence ID %d out of bounds (total %d)", seq, buf.Total)
	}

	buf.LastUpdate = time.Now()

	isNew := false

	if buf.File != nil {
		wordIdx := int(seq) / 64
		bitIdx := uint(seq) % 64

		if (buf.SeenChunks[wordIdx] & (1 << bitIdx)) == 0 {
			_, err := buf.File.WriteAt(chunkData, int64(seq)*protocol.ChunkSize)
			if err != nil {
				return nil, fmt.Errorf("disk write failed: %v", err)
			}

			buf.SeenChunks[wordIdx] |= (1 << bitIdx)
			buf.Received++
			isNew = true
		}
	} else {
		// RAM-based chunks must store the data for longer than the handleChunk call.
		// Since 'chunkData' comes from the transient pool buffer, we MUST copy it.
		if _, have := buf.Chunks[seq]; !have {
			storedChunk := make([]byte, len(chunkData))
			copy(storedChunk, chunkData)

			buf.Chunks[seq] = storedChunk
			buf.Received++
			isNew = true
		}
	}

	isComplete := buf.Received == buf.Total

	var finalPayload []byte
	if isComplete {
		p.chunkMu.Lock()
		delete(p.chunkBuffers, transferID)
		p.chunkMu.Unlock()

		if buf.File != nil {
			buf.File.Close()
			if p.OnFileComplete != nil {
				p.OnFileComplete(remote, buf.FilePath)
			}
			return []byte("ACK"), nil
		}

		dispatchOp := origOp

		finalLen := 0
		for i := 0; i < int(total); i++ {
			if d, ok := buf.Chunks[uint16(i)]; ok {
				finalLen += len(d)
			}
		}

		if finalLen > MaxPayloadSize {
			p.PacketsDropped.Add(1)
			return nil, errors.New("reassembled payload too large")
		}

		finalPayload = make([]byte, 0, finalLen)
		for i := 0; i < int(total); i++ {
			if d, ok := buf.Chunks[uint16(i)]; ok {
				finalPayload = append(finalPayload, d...)
			}
		}

		p.handlersMu.RLock()
		handler, ok := p.handlers[dispatchOp]
		p.handlersMu.RUnlock()

		if ok {
			return handler(remote, finalPayload)
		}
	} else if !isNew {
		return []byte("ACK"), nil
	}

	return []byte("ACK"), nil
}

func (p *Peer) pruneStaleChunks() {
	now := time.Now()
	for id, buf := range p.chunkBuffers {
		buf.Lock()
		if now.Sub(buf.LastUpdate) > 30*time.Second {
			if buf.File != nil {
				buf.File.Close()
				os.Remove(buf.FilePath)
			}
			delete(p.chunkBuffers, id)
		}
		buf.Unlock()
	}
}

// StartChunkGC initiates a background routine to periodically clean up stale or incomplete transfers.
func (p *Peer) StartChunkGC() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			p.chunkMu.Lock()
			p.pruneStaleChunks()
			p.chunkMu.Unlock()
		}
	}()
}