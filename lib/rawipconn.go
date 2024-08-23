//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package lib

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
	isServer           bool
	key                string
	pcapIface          *net.Interface
	handle             *pcap.Handle
	outputChan         chan *gopacket.Packet
	rawIPConnCloseChan chan *RawIPConn
}

type RawIPConnConfig struct {
	localIP  net.IP
	remoteIP net.IP // only used for client connection
	protocol layers.IPProtocol
}

// RawIPConn represents a connection for raw IP packets.
type RawIPConn struct {
	params        *RawIPConnParams
	config        *RawIPConnConfig
	readDeadline  time.Time
	inputChan     chan *gopacket.Packet
	tcpSignalChan chan *gopacket.Packet // to receive TCP signalling packets sniffed by pcapSession. For client side, it's SYN and ACK. For Server, it's SYN-ACK
	isClosed      bool
	mu            sync.Mutex
}

func NewRawIPConn(params *RawIPConnParams, config *RawIPConnConfig) (*RawIPConn, error) {
	conn := &RawIPConn{
		params:        params,
		config:        config,
		inputChan:     make(chan *gopacket.Packet),
		tcpSignalChan: make(chan *gopacket.Packet),
		mu:            sync.Mutex{},
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
			return 0, &TimeoutError{msg: "read timeout"}
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

// ReadFrom reads a packet from the RawIPConn and returns the payload and the source address.
func (conn *RawIPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
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
			return 0, nil, fmt.Errorf("connection closed")
		}
	} else {
		// Non-blocking read
		select {
		case packet, ok = <-conn.inputChan:
			if !ok {
				return 0, nil, fmt.Errorf("connection closed")
			}
		case <-time.After(time.Until(conn.readDeadline)):
			return 0, nil, &TimeoutError{msg: "read timeout"}
		}
	}

	// Extract the L4 payload and source IP
	if ipLayer := (*packet).Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if ip.Protocol == conn.config.protocol {
			copy(buffer, ip.Payload)
			return len(ip.Payload), &net.IPAddr{IP: ip.SrcIP}, nil
		}
	}

	return 0, nil, fmt.Errorf("no valid L4 payload found")
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
		SrcIP:    conn.config.localIP,
		DstIP:    conn.config.remoteIP,
	}

	// Serialize the packet.
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(data))
	if err != nil {
		return 0, err
	}

	// Create a gopacket.Packet from the serialized data
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	// Send the L3 packet to pcapSession's outputChan
	conn.params.outputChan <- &packet

	return len(data), nil
}

// WriteTo sends data to the specified destination address.
func (conn *RawIPConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Type assert the address to net.IPAddr
	ipAddr, ok := addr.(*net.IPAddr)
	if !ok {
		return 0, fmt.Errorf("unsupported address type")
	}

	// Create the L3 packet (IPv4 layer)
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: conn.config.protocol,
		SrcIP:    conn.config.localIP,
		DstIP:    ipAddr.IP,
	}

	// Serialize the packet.
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(data))
	if err != nil {
		return 0, err
	}

	// Create a gopacket.Packet from the serialized data
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

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
	log.Printf("Raw IPConn %s->%s with protocol id %d closed.\n", conn.config.localIP, conn.config.remoteIP, conn.config.protocol)
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

func (conn *RawIPConn) LocalIP() net.IP {
	return conn.config.localIP
}

func (conn *RawIPConn) RemoteIP() net.IP {
	return conn.config.remoteIP
}

type TimeoutError struct {
	msg string
}

func (e *TimeoutError) Error() string {
	return e.msg
}

func (e *TimeoutError) Timeout() bool {
	return true
}

func (e *TimeoutError) Temporary() bool {
	return false
}
