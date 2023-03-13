package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
)

func GetOui() (map[string]string, error) {
	ouiFile, err := os.Open("arpscan/ieee-oui.txt")
	if err != nil {
		log.Println("open ieee-oui.txt error ", err)
		return nil, err
	}
	defer ouiFile.Close()
	ouiReader := bufio.NewReader(ouiFile)
	oui := make(map[string]string)
	for {
		line, _, err := ouiReader.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		item := strings.Split(string(line), "\t")
		if len(item) != 2 {
			continue
		}
		oui[item[0]] = item[1]
	}
	return oui, nil
}

func GetOuiPrefix(mac net.HardwareAddr) (string, string) {
	ret1 := strings.ToUpper(strings.Replace(mac.String()[:8], ":", "", -1))
	ret2 := strings.ToUpper(strings.Replace(mac.String()[:13], ":", "", -1))
	return ret1, ret2
}

func GetGateways() []net.IP {
	ret := []net.IP{}
	netlinks, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		log.Fatal(err)
	}
	nmsg, err := syscall.ParseNetlinkMessage(netlinks)
	if err != nil {
		log.Fatal(err)
	}
	for _, m := range nmsg {
		if m.Header.Type == syscall.RTM_NEWROUTE {
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				log.Fatal(err)
			}
			for _, attr := range attrs {
				if attr.Attr.Type == syscall.RTA_GATEWAY {
					ret = append(ret, attr.Value)
				}
			}
		}
	}
	return ret
}

func IP2Uint32(ip net.IP) uint32 {
	var sum uint32
	sum += uint32(ip[0]) << 24
	sum += uint32(ip[1]) << 16
	sum += uint32(ip[2]) << 8
	return sum + uint32(ip[3])
}

func IPMask2Uint32(mask net.IPMask) uint32 {
	return IP2Uint32(net.IP(mask))
}
