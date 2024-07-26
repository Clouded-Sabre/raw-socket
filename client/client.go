package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	rawsocket "github.com/Clouded-Sabre/rawsocket/lib"
	"github.com/google/gopacket"
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

	startClient(core, config)
}

func startClient(core *rawsocket.RawSocketCore, config *Config) {
	conn, err := core.DialIP(config.Protocol, config.sourceIP, config.serverIP)
	if err != nil {
		log.Fatalf("Failed to dial to server IP %s: %v", config.serverIP, err)
	}
	defer conn.Close()

	var (
		wg       = sync.WaitGroup{}
		stopChan = make(chan struct{})
	)
	// start Handle incoming responses first to avoid possible response miss
	go receiveResponses(conn, stopChan, &wg)

	// Start sending packets with sequence IDs
	go sendPackets(conn, config)
}

func sendPackets(conn *rawsocket.RawIPConn, config *Config) {
	for i := 0; i < 10; i++ {
		message := fmt.Sprintf("packet Seq:%d", i)

		switch config.Protocol {
		case layers.IPProtocolUDP:
			sendUDPPacket(conn, config, message)
		case layers.IPProtocolTCP:
			sendTCPPacket(conn, config, message)
		case layers.IPProtocolICMPv4:
			sendICMPPacket(conn, message)
		default:
			log.Fatalf("Unsupported protocol: %v", config.Protocol)
		}

		time.Sleep(1 * time.Second)
	}
}

func sendUDPPacket(conn *rawsocket.RawIPConn, config *Config, message string) {
	srcIP, _, _, _ := rawsocket.GetLocalIP(config.serverIP)
	udpLayer := &layers.UDP{
		SrcPort: 12345,
		DstPort: 54321,
		Length:  8 + uint16(len(message)), // UDP header length + payload length
	}
	udpLayer.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: srcIP,
		DstIP: config.serverIP,
	})

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, udpLayer, gopacket.Payload([]byte(message)))
	if err != nil {
		log.Fatalf("Failed to serialize UDP packet: %v", err)
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Fatalf("Failed to send UDP packet: %v", err)
	}
}

func sendTCPPacket(conn *rawsocket.RawIPConn, config *Config, message string) {
	srcIP, _, _, _ := rawsocket.GetLocalIP(config.serverIP)
	tcpLayer := &layers.TCP{
		SrcPort: 12345,
		DstPort: 54321,
		Seq:     1,
		Window:  1500,
	}
	tcpLayer.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: srcIP,
		DstIP: config.serverIP,
	})

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, tcpLayer, gopacket.Payload([]byte(message)))
	if err != nil {
		log.Fatalf("Failed to serialize TCP packet: %v", err)
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Fatalf("Failed to send TCP packet: %v", err)
	}
}

func sendICMPPacket(conn *rawsocket.RawIPConn, message string) {
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0), // Echo request
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, icmpLayer, gopacket.Payload([]byte(message)))
	if err != nil {
		log.Fatalf("Failed to serialize ICMP packet: %v", err)
	}

	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Fatalf("Failed to send ICMP packet: %v", err)
	}
}

func receiveResponses(conn *rawsocket.RawIPConn, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	buffer := make([]byte, 1024)
	for {
		select {
		case <-stopChan:
			log.Println("receiveResponses got stop signal. Exitting...")
			return
		default:
			n, err := conn.Read(buffer)
			if err != nil {
				log.Fatalf("Error reading response: %v", err)
			}
			fmt.Printf("Received response: %s\n", buffer[:n])
		}

	}
}
