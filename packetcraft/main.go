package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	networkInterface = "lo"
	buffer           gopacket.SerializeBuffer
	options          gopacket.SerializeOptions
)

func main() {
	handle, err := pcap.OpenLive(
		networkInterface,
		1024,
		false,
		pcap.BlockForever,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ethernetLayer := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		DstMAC:       net.HardwareAddr{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4Layer := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{127, 0, 0, 1},
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := layers.TCP{
		Window:  5000,
		SrcPort: layers.TCPPort(55555),
		DstPort: layers.TCPPort(1337),
		SYN:     true,
	}
	tcpLayer.SetNetworkLayerForChecksum(&ipv4Layer)

	options = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&ethernetLayer,
		&ipv4Layer,
		&tcpLayer,
	)

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, net.IP{127, 0, 0, 1}, net.IP{127, 0, 0, 1})

	handle.WritePacketData(buffer.Bytes())

	fmt.Printf("%v\n", ipFlow)

	handle.ReadPacketData()
}
