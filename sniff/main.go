package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"

	"github.com/google/gopacket/pcap"
)

func main() {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	for i, iface := range ifaces {
		fmt.Printf("Interface #%d\nName: %s\nIP addresses:\n", i, iface.Name)
		for _, addr := range iface.Addresses {
			fmt.Println(addr.IP)
		}
		fmt.Printf("Description: %s\n\n", iface.Description)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Interface to use: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}
	input = strings.Trim(input, "\n")
	input = strings.Trim(input, "\r")
	input = strings.TrimSpace(input)

	handle, err := pcap.OpenLive(
		input,
		1024,
		false,
		pcap.BlockForever,
	)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	fmt.Println("Packet capture is started, press CTRL+C to stop packet capture")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Print the metadata
		fmt.Printf("\n[Metadata: %s]\n", packet.Metadata().CaptureInfo.Timestamp)

		fmt.Println(packet)
	}
}
