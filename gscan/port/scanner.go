package port

type PortScanner struct {
	Stop chan struct{}
}

func New() *PortScanner {
	p := &PortScanner{
		Stop: make(chan struct{}),
	}

	return p
}

func (p *PortScanner) Close() {
	<-p.Stop
}

func (p *PortScanner) Scan() {
	TCP()
}
