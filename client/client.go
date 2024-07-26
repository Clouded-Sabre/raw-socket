package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	rawsocket "github.com/Clouded-Sabre/rawsocket/lib"
	"github.com/google/gopacket/layers"
)

type Config struct {
	serverIP          net.IP
	sourceIP          net.IP
	Protocol          layers.IPProtocol
	ARPRequestTimeout int
	ARPCacheTimeout   int
}

func parseArgs() *Config {
	serverIPStr := flag.String("serverIP", "", "IP address of IPConn server")
	sourceIPStr := flag.String("sourceIP", "", "IP address of local source address")
	protocol := flag.String("protocol", "tcp", "Protocol to use (tcp/udp)")
	arpCacheTimeout := flag.Int("arpCacheTimeout", 30, "ARP cache timeout in seconds")
	arpRequestTimeout := flag.Int("arpRequestTimeout", 60, "ARP request timeout in seconds")

	flag.Parse()

	if *serverIPStr == "" {
		log.Println("server IP address is required")
		flag.Usage()
		return nil
	}

	serverIP := net.ParseIP(*serverIPStr)
	if serverIP == nil {
		log.Println("Listening IP address is malformed", *serverIPStr)
		return nil
	}

	var sourceIP net.IP
	if *sourceIPStr == "" {
		sourceIP = nil
	} else {
		sourceIP = net.ParseIP(*sourceIPStr)
		if sourceIP == nil {
			log.Println("local source IP address is malformed", *sourceIPStr)
			return nil
		}
	}

	// Convert protocol to layers.IPProtocol
	ipProtocol, err := stringToIPProtocol(*protocol)
	if err != nil {
		return nil
	}

	return &Config{
		serverIP:          serverIP,
		sourceIP:          sourceIP,
		Protocol:          ipProtocol,
		ARPRequestTimeout: *arpRequestTimeout,
		ARPCacheTimeout:   *arpCacheTimeout,
	}
}

func stringToIPProtocol(proto string) (layers.IPProtocol, error) {
	switch strings.ToLower(proto) {
	case "tcp":
		return layers.IPProtocolTCP, nil
	case "udp":
		return layers.IPProtocolUDP, nil
	case "icmp":
		return layers.IPProtocolICMPv4, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func main() {
	config := parseArgs()
	if config == nil {
		return
	}

	// Create the RawSocketCore
	core := rawsocket.NewRawSocketCore(config.ARPCacheTimeout, config.ARPRequestTimeout)

	conn, err := core.DialIP(config.Protocol, config.sourceIP, config.serverIP)
	if err != nil {
		log.Fatalf("Failed to dial to server IP %s: %v", config.serverIP, err)
	}
	defer conn.Close()

	// Send a test packet
	message := "Hello from client"
	_, err = conn.Write([]byte(message))
	if err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}

	fmt.Printf("Client sent message to server %s:%s: %s\n", config.serverIP, config.Protocol, message)
}
