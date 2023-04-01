package port

import (
	"fmt"
	"net"
	"time"
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

func (p *PortScan) TCPScan(ipList []net.IP) *TCPScanner {
	tcp := InitialTCPScanner()

	fmt.Println("Start Recv And Scan")
	go tcp.Recv()
	go tcp.Scan()

	go tcp.GenerateTarget(ipList)

	go tcp.CheckIPList(ipList)

	time.Sleep(5 * time.Second)

	return tcp

}

func (p *PortScan) UDPScan(ipList []net.IP) {
	udp := InitialUDPScanner()

	go udp.Recv()
}

func (p *PortScan) Recv() {

}

func (p *PortScan) ScanList(ipList []net.IP) {
	fmt.Println("Start Recv...")
}
