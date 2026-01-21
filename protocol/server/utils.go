package server

import (
	"encoding/base64"
)

// ServerToken represents the structure encoded into the server connection string.
// It contains all the necessary information for a client to connect and authenticate
// with a Rendezvous Server.
type ServerToken struct {
	Addr    string // The network address of the server (IP:Port)
	PEM     string // The server's Ed25519 Signing Public Key (PEM format)
	EncPEM  string // The server's X25519 Encryption Public Key (PEM format)
}

// EncodeServerToken creates a base64 encoded string containing the server's connection details.
// This string serves as an easy-to-share "invite code" for configuring clients.
//
// Parameters:
//   - addr: The address of the server (e.g., "1.2.3.4:14228").
//   - signPEM: The server's signing public key.
//   - encPEM: The server's encryption public key.
//
// Returns:
//   - A base64 encoded string representing the serialized ServerToken.
func EncodeServerToken(addr, signPEM, encPEM string) (string, error) {
	token := ServerToken{Addr: addr, PEM: signPEM, EncPEM: encPEM}

	buf := make([]byte, token.Size())
	token.Marshal(0, buf)

	return base64.StdEncoding.EncodeToString(buf), nil
}

// DecodeServerToken parses a base64 connection string back into a ServerToken struct.
//
// Parameters:
//   - tokenStr: The base64 encoded connection string.
//
// Returns:
//   - A pointer to the populated ServerToken struct, or an error if decoding fails.
func DecodeServerToken(tokenStr string) (*ServerToken, error) {
	data, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, err
	}
	var token ServerToken

	 _, err = token.Unmarshal(0, data)

	return &token, err
}