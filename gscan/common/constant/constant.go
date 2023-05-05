package constant

// icmp Scan Sequence and ID
const (
	ICMPId  uint16 = 23333
	ICMPSeq uint16 = 12345
)

// recevier register name
const (
	ICMPREGISTER_NAME string = "ICMP"
	TCPREGISTER_NAME  string = "TCP"
	UDPREGISTER_NAME  string = "UDP"
)

// TCP Scan TYPE
const (
	TYPE_FULLTCP uint8 = 1
	TYPE_HALFTCP uint8 = 2
)

// Default Channel Size
const (
	CHANNEL_SIZE uint8 = 10
)
