package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const maxPackets = 5

func capture() {
	fmt.Printf("I am initiating the packet capture. After %d packets, I will stop\n\n", maxPackets)

	f, err := os.Create(outputFileName)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	defer handle.Close()

	i := 0

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if i == maxPackets {
			break
		}

		fmt.Printf("%d\n", i+1)

		err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			break
		}

		i++
	}

	fmt.Println("\nPacket capture is finished")
}
