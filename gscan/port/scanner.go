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

func (p *PortScan) TCPScan(ipList []net.IP, scanType uint8) *TCPScanner {
	tcp := InitialTCPScanner(scanType)

	fmt.Println("Start Recv And Scan")
	go tcp.Recv()
	go tcp.Scan()

	go tcp.GenerateTarget(ipList)

	go tcp.CheckIPList(ipList)

	time.Sleep(tcp.Timeout)

	return tcp

}

func (p *PortScan) UDPScan(ipList []net.IP) *UDPScanner {
	udp := InitialUDPScanner()

	fmt.Println("Start Recv")
	go udp.Recv()

	fmt.Println("Start Scan")
	go udp.Scan()

	fmt.Println("Start Generate")
	go udp.GenerateTarget(ipList)

	// go udp.CheckIPList(ipList)

	time.Sleep(5 * time.Second)

	return udp
}

func (p *PortScan) Recv() {

}

func (p *PortScan) ScanList(ipList []net.IP) {
	fmt.Println("Start Recv...")
}
