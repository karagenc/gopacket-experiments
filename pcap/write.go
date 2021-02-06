package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	maxPackets = 5
)

func write() {
	fmt.Printf("Capturing %d packets\n\n", maxPackets)

	f, err := os.Create(outputFileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(
		1024, // Snapshot length
		layers.LinkTypeEthernet,
	)

	handle, err := pcap.OpenLive(networkInterface,
		1024,
		false,
		pcap.BlockForever,
	)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	i := 0

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if i == maxPackets {
			break
		}

		fmt.Printf("Captured packet %d\n", i+1)

		err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			panic(err)
		}

		i++
	}

	fmt.Println("\nFinished packet capture :) Let me show you")
}
