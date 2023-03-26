//go:build darwin
// +build darwin

package common

import (
	"bytes"
	"fmt"
	"net"
)

type Interface struct {
	Port string
	Name string
}

func GetGateways() []net.IP {
	ifs := GetInterfaces()
	//fmt.Println(ifs)
	baseCommand := "networksetup -getinfo \"%s\""

	// 做两次筛选
	// 第一次为关键字：IP address Subnet mask Router
	// 第二次为mac地址：查询是否存在mac地址，通过匹配null关键字
	gateways := []net.IP{}


	for _, iface := range ifs {
		if out := Exec(fmt.Sprintf(baseCommand, iface.Port)); out != nil {

			// 第一次关键字过滤
			if bytes.Index(out, []byte("IP address")) == -1 ||
				bytes.Index(out, []byte("Subnet mask")) == -1 ||
				bytes.Index(out, []byte("Router")) == -1 {
				continue
			}

			tmp := bytes.Split(out, []byte{0x0a})[1:] // 通过换行符进行分割

			// 第二次mac地址值校验
			macAddr := bytes.Split(tmp[len(tmp)-2], []byte(": "))
			if bytes.Index(macAddr[1], []byte("null")) != -1{
				continue
			}

			// 获取网卡其他信息
			gateway := fmt.Sprintf("%s", bytes.Split(tmp[2], []byte(": "))[1])
			gateways = append(gateways, net.ParseIP(gateway).To4())
		}
	}

	return gateways

}

func GetInterfaces() []Interface{
	out := Exec("networksetup -listnetworkserviceorder | grep \"Hardware Port\"")
	res := bytes.Split(out, []byte("\n"))

	ifs := []Interface{}
	for _, r := range res{
		r2 := bytes.Split(r, []byte(", "))

		if len(r2) == 2 {
			r3 := bytes.Split(r2[0], []byte(": "))
			r4 := bytes.Split(r2[1], []byte(": "))
			r5 := bytes.Replace(r4[1], []byte(")"), []byte(""), -1)
			//fmt.Printf("%s %s\n", r3[1], r5)
			ifs = append(ifs, Interface{
				Port: fmt.Sprintf("%s", r3[1]),
				Name: fmt.Sprintf("%s", r5),
			})
		}

	}

	return ifs
}
