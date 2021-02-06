package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	networkInterface = "wlan0"
)

func main() {
	handle, err := pcap.OpenLive(networkInterface,
		1024,
		true,
		pcap.BlockForever,
	)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	i := 0

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if i == 5 {
			break
		}

		fmt.Printf("\n### Packet ###\n")

		fmt.Println(packet)

		dot11Layer := packet.Layer(layers.LayerTypeDot11)
		if dot11Layer != nil {
			dot11, _ := dot11Layer.(*layers.Dot11)
			fmt.Printf("Type: %s\nAddress 1: %s\nAddress 2: %s\nAddress 3: %s\nAddress 4: %s\n", dot11.Type, dot11.Address1, dot11.Address2, dot11.Address3, dot11.Address4)
		}

		dot11Infolayer := packet.Layer(layers.LayerTypeDot11InformationElement)
		if dot11Infolayer != nil {
			dot11info, _ := dot11Infolayer.(*layers.Dot11InformationElement)
			fmt.Printf("SSID: %s\n", dot11info.Info)
		}

		fmt.Println("### End of packet ###")

		i++
	}
	fmt.Printf("\n")
}
