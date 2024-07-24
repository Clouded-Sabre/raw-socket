package main

/*import (
	"flag"
	"fmt"
	"net"
	"os"
)

var destIP string

func init() {
	// Define CLI flags for server IP and port
	flag.StringVar(&destIP, "destIP", "", "Destination IP address")
	flag.Parse()
}

func main() {
	if destIP == "" {
		fmt.Println("Please provide a destination IP address using the -destIP flag")
		os.Exit(1)
	}

	// Replace with your target destination IP
	targetIP := net.ParseIP(destIP)

	localIP, err := getLocalIP(targetIP)
	if err != nil {
		fmt.Printf("Error finding local IP: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Local IP for routing to %s: %s\n", targetIP, localIP)
}*/
