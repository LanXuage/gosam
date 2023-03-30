package port

import (
	"fmt"
	"net"
)

type PortScan struct {
	Stop chan struct{}
}

func New() *PortScan {
	p := &PortScan{
		Stop: make(chan struct{}),
	}

	return p
}

func (p *PortScan) Close() {
	<-p.Stop
}

func (p *PortScan) Scan(ipList []net.IP) {
	for _, ip := range ipList {
		fmt.Println(ip)
	}
}

func (p *PortScan) Recv() {

}

func (p *PortScan) ScanList(ipList []net.IP) {
	fmt.Println("Start Recv...")
	go p.Scan(ipList)
}
