package main

const (
	networkInterface = "wlan0"
	outputFileName   = "capture.pcap"
)

func main() {
	// ### Write to file ###
	write()

	// ### Read from pcap ###
	read()
}
