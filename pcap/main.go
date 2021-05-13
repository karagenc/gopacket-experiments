package main

const (
	networkInterface = "wlan0"
	outputFileName   = "capture.pcap"
)

func main() {
	capture() // Capture and write to file.
	read()    // Read from pcap.
}
