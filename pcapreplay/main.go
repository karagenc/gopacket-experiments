package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	networkInterface = "wlan0"
	inputFile        = "input.pcap"
)

func main() {
	pcapHandle, err := pcap.OpenOffline(inputFile)
	if err != nil {
		log.Fatal(err)
	}

	handle, err := pcap.OpenLive(networkInterface,
		1024,
		false,
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Sending packets")

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		err = handle.WritePacketData(packet.Data())
		if err != nil {
			fmt.Printf("Failed to send a packet: %v\n", err)
		}
	}

	fmt.Println("Finished")
}
