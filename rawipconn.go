//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type RawIPConnParams struct {
	key                string
	pcapIface          *net.Interface
	handle             *pcap.Handle
	outputChan         chan *gopacket.Packet
	rawIPConnCloseChan chan *RawIPConn
}

type RawIPConnConfig struct {
	srcIP    net.IP
	dstIP    net.IP
	protocol layers.IPProtocol
}

// RawIPConn represents a connection for raw IP packets.
type RawIPConn struct {
	params       *RawIPConnParams
	config       *RawIPConnConfig
	readDeadline time.Time
	inputChan    chan *gopacket.Packet
	isClosed     bool
	mu           sync.Mutex
}

func NewRawIPConn(params *RawIPConnParams, config *RawIPConnConfig) (*RawIPConn, error) {
	conn := &RawIPConn{
		params:    params,
		config:    config,
		inputChan: make(chan *gopacket.Packet),
		mu:        sync.Mutex{},
	}

	return conn, nil
}

// Read reads data from the RawIPConn.
func (conn *RawIPConn) Read(buffer []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	var (
		packet *gopacket.Packet
		ok     bool
	)

	// Check if the read deadline is in the past
	if time.Now().After(conn.readDeadline) {
		// Perform a blocking read
		packet, ok = <-conn.inputChan
		if !ok {
			return 0, fmt.Errorf("connection closed")
		}
	} else {
		// non-blocking read
		select {
		case packet, ok = <-conn.inputChan:
			if !ok {
				return 0, fmt.Errorf("connection closed")
			}
		case <-time.After(time.Until(conn.readDeadline)):
			return 0, fmt.Errorf("read timeout")
		}
	}

	// Extract the L4 payload
	if ipLayer := (*packet).Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip.Protocol == conn.config.protocol {
			copy(buffer, ip.Payload)
			return len(ip.Payload), nil
		}
	}

	return 0, fmt.Errorf("no valid L4 payload found")
}

// Write writes data to the RawIPConn.
func (conn *RawIPConn) Write(data []byte) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Create the L3 packet (IPv4 layer)
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: conn.config.protocol,
		SrcIP:    conn.config.srcIP,
		DstIP:    conn.config.dstIP,
	}

	// Serialize the packet.
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(data))
	if err != nil {
		return 0, err
	}

	// Create a gopacket.Packet from the serialized data
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Send the L3 packet to pcapSession's outputChan
	conn.params.outputChan <- &packet

	return len(data), nil
}

func (conn *RawIPConn) SetReadDeadline(t time.Time) error {
	conn.readDeadline = t
	return nil
}

func (conn *RawIPConn) getKey() string {
	return conn.params.key
}

// Close closes the RawIPConn.
func (conn *RawIPConn) Close() error {
	if conn.isClosed {
		return nil
	}
	conn.isClosed = true

	close(conn.inputChan)
	//conn.params.handle.Close()
	log.Printf("Raw IPConn %s->%s with protocol id %d closed.\n", conn.config.srcIP, conn.config.dstIP, conn.config.protocol)
	return nil
}

// Htons converts a 16-bit number from host byte order to network byte order.
func Htons(port uint16) uint16 {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, port)
	return binary.LittleEndian.Uint16(bytes)
}

// findInterfaceByIP finds the network interface by its IP address.
func findInterfaceByIP(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ipAddr net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ipAddr = v.IP
			case *net.IPAddr:
				ipAddr = v.IP
			}

			if ipAddr != nil && ipAddr.Equal(ip) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found with IP %v", ip)
}
