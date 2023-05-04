package port

import (
	"gscan/arp"
	"gscan/common"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var arpInstance = arp.GetARPScanner()
var receiver = common.GetReceiver()

const (
	TCP_REGISTER_NAME string = "TCP"
)

type TCPResult struct {
	IP   net.IP
	Port layers.TCPPort
}

type TCPTarget struct {
	SrcIP   []byte
	SrcPort layers.TCPPort
	DstIP   []byte
	DstPort layers.TCPPort
	Ack     uint32
	SrcMac  net.HardwareAddr
	DstMac  net.HardwareAddr
	Handle  *pcap.Handle
}

var halfTCPInstance = newHalfTCPScanner()

func GetHalfTCPScanner() *HalfTCPScanner {
	return halfTCPInstance
}

var tcpInstance = newTCPScanner()

func GetTCPScanner() *TCPScanner {
	return tcpInstance
}
