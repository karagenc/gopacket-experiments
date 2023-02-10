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

	for _, iface := range ifaces {
		fmt.Printf("Name: %s\n", iface.Name)
		if len(iface.Addresses) > 0 {
			fmt.Println("IP addresses:")
		}
		for _, addr := range iface.Addresses {
			fmt.Printf("    %s\n", addr.IP)
		}
		if iface.Description != "" {
			fmt.Printf("Description: %s\n", iface.Description)
		}
		fmt.Printf("\n")
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

	fmt.Println("Packet capture is started, press CTRL+C to stop")

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
	fmt.Println("\nFinished")
}
