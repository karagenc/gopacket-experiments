package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func read() {
	pcapHandle, err := pcap.OpenOffline(outputFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer pcapHandle.Close()

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Printf("\n%s\n", packet)
	}

	fmt.Printf("\n")
}
