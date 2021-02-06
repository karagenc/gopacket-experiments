package main

import (
	"fmt"

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
		panic(err)
	}

	liveHandle, err := pcap.OpenLive(networkInterface,
		1024,
		false,
		pcap.BlockForever,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Sending packets")

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		err = liveHandle.WritePacketData(packet.Data())
		if err != nil {
			fmt.Printf("Couldn't send packet, details:%s\n", err.Error())
		}
	}

	fmt.Println("Successful!")
}
