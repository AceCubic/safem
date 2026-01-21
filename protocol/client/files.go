package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/banditmoscow1337/safem/protocol"
	"github.com/banditmoscow1337/safem/protocol/cryptolib"
)

// FileTransferState maintains the progress and handles of an active file download.
type FileTransferState struct {
	// File is the open file handle for the incoming transfer.
	File *os.File
	// Writer provides buffered I/O for writing to the file.
	Writer *bufio.Writer
	// OriginalName is the filename suggested by the sender.
	OriginalName string
	// TotalSize is the total expected size of the file in bytes.
	TotalSize int64
	// BytesReceived is the count of bytes successfully written to disk so far.
	BytesReceived int64
	// SavePath is the absolute or relative path where the file is being saved.
	SavePath string
	// SenderID is the cryptographic ID of the peer sending the file.
	SenderID string

	// BlockCh is a buffered channel for queuing incoming data chunks before writing.
	BlockCh chan []byte
}

// fileMeta represents the metadata exchanged during the file transfer handshake.
type fileMeta struct {
	Name string
	Size int64
	ID   string // Unique Transfer ID
}

// incomingFileReq holds metadata for a transfer waiting for user acceptance.
type incomingFileReq struct {
	Meta       fileMeta
	SenderID   string
	SenderAddr string
}

// SendFile initiates a file upload to the target peer.
// It requests permission, waits for acceptance, and then streams the file in blocks.
func (c *Client) SendFile(ctx context.Context, targetID, path string) error {
	sess, ok := c.Peer.GetSession(targetID)
	if !ok || sess.Addr == "" {
		return fmt.Errorf("peer offline")
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	// Generate a unique ID for this transfer session
	rawID, _ := cryptolib.GenerateRandomBytes(16)
	transferID := hex.EncodeToString(rawID)

	meta := fileMeta{
		Name: filepath.Base(path),
		Size: info.Size(),
		ID:   transferID,
	}

	metaBytes := make([]byte, meta.Sizer())
	meta.Marshal(0, metaBytes)

	// Setup channel to receive the peer's Acceptance/Rejection signal
	acceptCh := make(chan bool, 1)
	c.pendingResponsesMu.Lock()
	c.pendingResponses[transferID] = acceptCh
	c.pendingResponsesMu.Unlock()

	defer func() {
		c.pendingResponsesMu.Lock()
		delete(c.pendingResponses, transferID)
		c.pendingResponsesMu.Unlock()
	}()

	c.Events.OnLog("[Transfer] Requesting upload: %s...\n", meta.Name)
	resp, err := c.Peer.Call(ctx, sess.Addr, protocol.OpFileStart, metaBytes)
	if err != nil {
		return fmt.Errorf("failed to start transfer: %v", err)
	}

	// Wait for User Acceptance on the other side
	if string(resp) == "PENDING" {
		c.Events.OnLog("[Transfer] Waiting for %s to accept...\n", c.Peer.GetName(targetID))

		timeout := time.NewTimer(2 * time.Minute)
		defer timeout.Stop()

		select {
		case accepted := <-acceptCh:
			if !accepted {
				return fmt.Errorf("transfer rejected by user")
			}
			c.Events.OnLog("[Transfer] Accepted! Starting upload...\n")
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return fmt.Errorf("transfer timed out waiting for acceptance")
		}
	} else if string(resp) != "ACK" {
		return fmt.Errorf("peer rejected transfer")
	}

	// Stream file content
	const BlockSize = 4 * 1024 * 1024 // 4MB chunks

	// Reuse a single buffer for the entire upload loop.
	// Payload layout: [TransferID (16 bytes)][Data Chunk (up to BlockSize)]
	// We allocate enough space for header + max data once.
	payloadBuf := make([]byte, 16+BlockSize)

	// Pre-fill the TransferID since it remains constant
	copy(payloadBuf[0:16], rawID)

	var sent int64
	for {
		// Read directly into the buffer offset by 16 bytes.
		// payloadBuf[16:] is the slice where data goes.
		n, err := f.Read(payloadBuf[16:])
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		// Slice the buffer to the exact size of data read (Header + n)
		// This avoids allocating a new slice for 'payload'.
		chunkPayload := payloadBuf[:16+n]

		// SendLarge handles the reliable delivery of this block.
		// Note: SendLarge blocks until the chunk transfer is acknowledged (or sufficiently queued),
		// so it is safe to overwrite payloadBuf in the next iteration.
		if err := c.Peer.SendLarge(ctx, sess.Addr, protocol.OpFileBlock, chunkPayload); err != nil {
			return fmt.Errorf("upload failed at %d%%: %v", int(float64(sent)/float64(info.Size())*100), err)
		}
		sent += int64(n)
	}

	c.Events.OnLog("[Transfer] Upload complete.\n")
	return nil
}

// AcceptFileTransfer is called by the user to authorize an incoming file request.
// It creates the local file and notifies the sender to begin the data stream.
func (c *Client) AcceptFileTransfer(transferID string) error {
	c.pendingIncomingMu.Lock()
	req, ok := c.pendingIncoming[transferID]
	delete(c.pendingIncoming, transferID)
	c.pendingIncomingMu.Unlock()

	if !ok {
		return fmt.Errorf("request not found or expired")
	}

	// Prepare local file for writing
	safeName := filepath.Base(req.Meta.Name)
	savePath := fmt.Sprintf("received_%d_%s", time.Now().Unix(), safeName)

	f, err := os.Create(savePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}

	bw := bufio.NewWriter(f)

	// Buffer channel to absorb network bursts without blocking ACK if disk is slow
	blockCh := make(chan []byte, 16)

	state := &FileTransferState{
		File:          f,
		Writer:        bw,
		OriginalName:  safeName,
		TotalSize:     req.Meta.Size,
		BytesReceived: 0,
		SavePath:      savePath,
		SenderID:      req.SenderID,
		BlockCh:       blockCh,
	}

	c.transfersMu.Lock()
	c.transfers[req.Meta.ID] = state
	c.transfersMu.Unlock()

	// Start background writer
	go c.processTransfer(req.Meta.ID, state)

	senderName := c.Peer.GetName(req.SenderID)
	c.Events.OnLog("[Transfer] Starting download from %s: %s (%.2f MB)\n", senderName, safeName, float64(req.Meta.Size)/1024/1024)

	// Send OpFileAccept to notify the sender to begin streaming
	return c.Peer.SendFast(context.Background(), req.SenderAddr, protocol.OpFileAccept, []byte(transferID))
}

// processTransfer runs in a background goroutine to write file blocks to disk sequentially.
func (c *Client) processTransfer(transferID string, state *FileTransferState) {
	defer state.File.Close()

	for block := range state.BlockCh {
		n, err := state.Writer.Write(block)
		if err != nil {
			c.Events.OnLog("[Transfer] Disk write failed for %s: %v\n", state.OriginalName, err)
			break // Stop writing on error
		}
		state.BytesReceived += int64(n)

		if state.BytesReceived >= state.TotalSize {
			state.Writer.Flush()

			// Cleanup State
			c.transfersMu.Lock()
			delete(c.transfers, transferID)
			c.transfersMu.Unlock()

			// Notify Completion
			peerName := c.Peer.GetName(state.SenderID)
			c.Events.OnFileReceived(state.SenderID, peerName, state.SavePath)
			c.Events.OnLog("[Transfer] Download complete: %s\n", state.OriginalName)
			return
		}
	}
}

// RejectFileTransfer is called by the user to deny an incoming file request.
func (c *Client) RejectFileTransfer(transferID string) error {
	c.pendingIncomingMu.Lock()
	req, ok := c.pendingIncoming[transferID]
	delete(c.pendingIncoming, transferID)
	c.pendingIncomingMu.Unlock()

	if !ok {
		return nil // Already gone
	}

	c.Events.OnLog("[Transfer] Rejected file from %s\n", c.Peer.GetName(req.SenderID))
	return c.Peer.SendFast(context.Background(), req.SenderAddr, protocol.OpFileReject, []byte(transferID))
}

// Internal Handlers

// handleFile handles legacy small files reassembled in RAM (OpFile).
func (c *Client) handleFile(remote *net.UDPAddr, data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, nil
	}

	// Create a copy of data because we are going async and the network buffer will be reclaimed
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// Process asynchronously to avoid blocking the network loop with disk IO
	go func() {
		// RAM-backed payload: [Len uint16][Name][Data]
		nameLen := binary.BigEndian.Uint16(dataCopy[0:2])
		if len(dataCopy) < 2+int(nameLen) {
			c.Events.OnLog("Malformed legacy file payload from %s", remote.String())
			return
		}
		fileName := string(dataCopy[2 : 2+nameLen])
		source := bytes.NewReader(dataCopy[2+nameLen:])

		if _, err := c.saveIncomingFile(remote, fileName, source); err != nil {
			c.Events.OnLog("Failed to save legacy file: %v", err)
		}
	}()

	return protocol.PackStrings("ACK"), nil
}

// handleFileRef handles large files reassembled to a temp file by the lower P2P layer (OpChunk).
func (c *Client) handleFileRef(remote *net.UDPAddr, data []byte) ([]byte, error) {
	// Payload is the temp file path string provided by p2p package
	// This path is already on disk.
	tempPath := string(data)

	// Handle the final move/copy asynchronously
	go func() {
		tempFile, err := os.Open(tempPath)
		if err != nil {
			c.Events.OnLog("Failed to open temp file payload: %v", err)
			return
		}
		defer func() {
			tempFile.Close()
			os.Remove(tempPath) // Cleanup temp file
		}()

		// Parse Header: [Len uint16][Name][Data...]
		header := make([]byte, 2)
		if _, err := io.ReadFull(tempFile, header); err != nil {
			c.Events.OnLog("Failed to read name len: %v", err)
			return
		}
		actualNameLen := binary.BigEndian.Uint16(header)

		nameBuf := make([]byte, actualNameLen)
		if _, err := io.ReadFull(tempFile, nameBuf); err != nil {
			c.Events.OnLog("Failed to read actual name: %v", err)
			return
		}
		fileName := string(nameBuf)

		// tempFile cursor is now at the start of binary data
		if _, err := c.saveIncomingFile(remote, fileName, tempFile); err != nil {
			c.Events.OnLog("Failed to save chunked file: %v", err)
		}
	}()

	return protocol.PackStrings("ACK"), nil
}

// saveIncomingFile helper to stream data from Reader to a new file in CWD.
func (c *Client) saveIncomingFile(remote *net.UDPAddr, fileName string, source io.Reader) ([]byte, error) {
	id := c.Peer.GetID(remote.String())
	name := c.Peer.GetName(id)

	safeName := filepath.Base(fileName)
	savePath := fmt.Sprintf("received_%d_%s", time.Now().Unix(), safeName)

	destFile, err := os.Create(savePath)
	if err != nil {
		return nil, err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, source); err != nil {
		return nil, err
	}

	c.Events.OnFileReceived(id, name, savePath)
	return protocol.PackStrings("ACK"), nil
}

// handleFileStart handles the initial handshake for a streaming file transfer.
// It stores the request and triggers a UI event for the user to decide.
func (c *Client) handleFileStart(remote *net.UDPAddr, data []byte) ([]byte, error) {
	var meta fileMeta
	if _, err := meta.Unmarshal(0, data); err != nil {
		return nil, err
	}

	peerID := c.Peer.GetID(remote.String())

	req := incomingFileReq{
		Meta:       meta,
		SenderID:   peerID,
		SenderAddr: remote.String(),
	}

	c.pendingIncomingMu.Lock()
	c.pendingIncoming[meta.ID] = req
	c.pendingIncomingMu.Unlock()

	// Notify UI to show Acceptance Modal
	c.Events.OnFileRequest(meta.ID, peerID, meta.Name, meta.Size)

	// Tell sender to wait (state: PENDING)
	return []byte("PENDING"), nil
}

// handleFileAccept processes the "Accept" signal from the peer.
func (c *Client) handleFileAccept(remote *net.UDPAddr, data []byte) ([]byte, error) {
	transferID := string(data)

	c.pendingResponsesMu.Lock()
	if ch, ok := c.pendingResponses[transferID]; ok {
		select {
		case ch <- true:
		default:
		}
	}
	c.pendingResponsesMu.Unlock()
	return nil, nil
}

// handleFileReject processes the "Reject" signal from the peer.
func (c *Client) handleFileReject(remote *net.UDPAddr, data []byte) ([]byte, error) {
	transferID := string(data)

	c.pendingResponsesMu.Lock()
	if ch, ok := c.pendingResponses[transferID]; ok {
		select {
		case ch <- false:
		default:
		}
	}
	c.pendingResponsesMu.Unlock()
	return nil, nil
}

// handleFileBlock processes an incoming data chunk for an active transfer.
func (c *Client) handleFileBlock(remote *net.UDPAddr, data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("block too short")
	}
	// Extract Transfer ID from first 16 bytes
	transferID := hex.EncodeToString(data[0:16])

	// Lookup Transfer State
	c.transfersMu.Lock()
	state, exists := c.transfers[transferID]
	c.transfersMu.Unlock() // Unlock immediately

	if !exists {
		return nil, fmt.Errorf("unknown transfer")
	}

	// Make a copy of the block data because the network buffer 'data' is recycled
	blockCopy := make([]byte, len(data)-16)
	copy(blockCopy, data[16:])

	// Send to background writer
	// Using a buffered channel prevents slow disk IO from immediately blocking the network thread
	// unless the buffer fills up (backpressure).
	select {
	case state.BlockCh <- blockCopy:
		// Success
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("disk write backlog full, slow IO")
	}

	return []byte("ACK"), nil
}