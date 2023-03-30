package port

import (
	"log"
	"net"

	"github.com/google/gopacket/pcap"
)

type TCPScan struct {
	TargetIP   net.IP
	TargetPort uint16
	SrcIP      net.IP
	SrcPort    uint16
	Handle     *pcap.Handle
}

type TCPResult struct {
	IP       net.IP
	Port     uint16
	IsActive bool
}

func TCP() {
	handle, err := pcap.OpenLive("en0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	t := TCPScan{
		TargetIP:   net.ParseIP("192.168.0.1"),
		TargetPort: 80,
		SrcIP:      net.ParseIP("192.168.0.45"),
		SrcPort:    12345,
		Handle:     handle,
	}

}
