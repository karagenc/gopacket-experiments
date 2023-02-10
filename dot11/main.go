package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const networkInterface = "wlan0mon"

func main() {
	handle, err := pcap.OpenLive(networkInterface,
		1024,
		true,
		100*time.Millisecond,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("Packet capture is started, press CTRL+C to stop")
	go capture(handle)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(
		signalChan,
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
	)

	<-signalChan
	fmt.Println("\nExiting")
}

func capture(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Printf("\n\n")
		fmt.Println(packet)

		dot11Layer := packet.Layer(layers.LayerTypeDot11)
		if dot11Layer != nil {
			dot11, _ := dot11Layer.(*layers.Dot11)
			fmt.Printf("Type: %s\nAddress 1: %s\nAddress 2: %s\nAddress 3: %s\nAddress 4: %s\n", dot11.Type, dot11.Address1, dot11.Address2, dot11.Address3, dot11.Address4)
		}

		dot11InfoLayer := packet.Layer(layers.LayerTypeDot11InformationElement)
		if dot11InfoLayer != nil {
			dot11Info, _ := dot11InfoLayer.(*layers.Dot11InformationElement)
			if dot11Info.ID == layers.Dot11InformationElementIDSSID {
				fmt.Printf("SSID: %s\n", dot11Info.Info)
			}
		}
	}
}
