package icmp

import (
	"fmt"
	"gscan/arp"
)

type ICMPScanner struct {
	Stop     chan struct{}
	AScanner *arp.ARPScanner
}

func New() *ICMPScanner {
	icmpScanner := &ICMPScanner{
		Stop:     make(chan struct{}),
		AScanner: arp.New(),
	}
	go func() {
		for result := range icmpScanner.AScanner.ScanLocalNet() {
			fmt.Println(result)
		}
	}()
	return icmpScanner
}

func (icmpScanner *ICMPScanner) Close() {
	if icmpScanner.AScanner != nil {
		icmpScanner.AScanner.Close()
	}
}
