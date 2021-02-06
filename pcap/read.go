package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func read() {
	handle, err := pcap.OpenOffline(outputFileName)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Printf("\n### Packet ###\n%s\n### End of packet ###\n", packet)
	}

	fmt.Printf("\n")
}
