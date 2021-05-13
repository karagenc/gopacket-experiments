package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"

	"github.com/google/gopacket/pcap"
)

func main() {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	input = strings.Trim(input, "\n\r")
	input = strings.TrimSpace(input)

	handle, err := pcap.OpenLive(
		input,
		1024,
		false,
		100*time.Millisecond,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("Packet capture is started, press CTRL+C to stop packet capture")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go func() {
		for packet := range packetSource.Packets() {
			fmt.Println(packet)
		}
	}()

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
