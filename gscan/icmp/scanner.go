package icmp

import (
	"gscan/arp"
)

type ICMPScanner struct {
	AScanner *arp.ARPScanner
}
