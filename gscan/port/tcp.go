package port

import (
	"gscan/common"

	"github.com/google/gopacket"
)

type TCPScanner struct {
	HalfTCPScanner
}

func newTCPScanner() *TCPScanner {
	return &TCPScanner{
		HalfTCPScanner: *GetHalfTCPScanner(),
	}
}

func (t *TCPScanner) RecvTCP(packet gopacket.Packet) interface{} {
	if tcp, ip, eth := t.Unpack(packet); tcp != nil {
		if tcp.SYN {
			t.TargetCh <- &TCPTarget{
				SrcIP:   ip.DstIP,
				SrcPort: t.SrcPost,
				DstIP:   ip.SrcIP,
				DstPort: tcp.SrcPort,
				SrcMac:  eth.DstMAC,
				DstMac:  eth.SrcMAC,
				Ack:     tcp.Seq + 1,
				Handle:  common.GetInterfaceBySrcMac(eth.DstMAC).Handle,
			}
			return nil
		}
		t.Save(ip.SrcIP, tcp.SrcPort)
		return TCPResult{
			IP:   ip.SrcIP,
			Port: tcp.SrcPort,
		}
	}
	return nil
}
