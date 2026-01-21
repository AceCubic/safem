package main

import (
	"flag"
	"fmt"

	"github.com/banditmoscow1337/safem/protocol/cryptolib"
	"github.com/banditmoscow1337/safem/protocol/server"
)

func main() {
	// Parse command line flags
	port := flag.Int("port", 14888, "Listening port for the server")
	relay := flag.Bool("relay", false, "Enable realy functionality")
	flag.Parse()

	srv := server.New(*relay)
	
	addr, pubPEM, encPEM, err := srv.Start(*port)
	if err != nil {
		panic(err)
	}

	token, _ := server.EncodeServerToken(addr, pubPEM, encPEM) 

	fmt.Println("----------------------------------------------------------------")
	fmt.Println("SERVER STARTED (ID-BASED REGISTRY)")
	fmt.Printf("Listen Address: %s\n", addr)
	fmt.Printf("Server ID:      %s\n", cryptolib.Fingerprint(srv.Peer.PubKey)) 
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("CONNECTION STRING:\n%s\n", token)
	fmt.Println("----------------------------------------------------------------")
	select {}
}