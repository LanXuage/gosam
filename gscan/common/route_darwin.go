//go:build darwin
// +build darwin

package common

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

func GetGateways() []net.IP {
	//command := "route get default | grep gateway"
	//ip := Exec(command)
	//
	//return ip
	return []net.IP{{192,168,0,1}}
}

func Exec(command string) []net.IP {
	in := bytes.NewBuffer(nil)
	cmd := exec.Command("sh")

	cmd.Stdin = in
	in.WriteString(command)

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err.Error())
	}

	tmp := strings.Split(fmt.Sprintf("%s", out), ":")
	tmp2 := Replace(tmp[1], " ")
	tmp2 = Replace(tmp2, "\n")

	s := []net.IP{}
	s = append(s, net.ParseIP(tmp2))
	return s
}

func Replace(s string, old string) string{
	return strings.Replace(s, old, "", -1)
}
