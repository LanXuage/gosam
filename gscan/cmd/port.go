package cmd

import (
	"fmt"
	"gscan/common"
	"gscan/port"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	tcpScanner = port.GetTCPScanner()
	portCmd    = &cobra.Command{
		Use:   "port",
		Short: "PORT Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := common.GetLogger()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			icmpScanner.Timeout = time.Second * time.Duration(timeout)
			hosts, _ := cmd.Flags().GetStringArray("host")
			logger.Debug("runE", zap.Any("host", hosts))
			if len(hosts) == 0 {
				all, _ := cmd.Flags().GetBool("all")
				if all {
					timeoutCh := tcpScanner.ScanLocalNet()
					normalPrintfTCP(timeoutCh, tcpScanner.ResultCh)
				} else {
					cmd.Help()
				}
			}
			tcpScanner.UseFullTCP, _ = cmd.Flags().GetBool("full")
			ports, _ := cmd.Flags().GetStringArray("port")
			if len(ports) != 0 {
				tcpScanner.PortScanType = port.CUSTOM_PORTS
				for _, port := range ports {
					tmp, _ := strconv.ParseUint(port, 10, 16)
					tcpScanner.Ports = append(tcpScanner.Ports, layers.TCPPort(tmp))
				}
			}
			for _, host := range hosts {
				if ip, err := netip.ParseAddr(host); err != nil {
					if prefix, err := netip.ParsePrefix(host); err != nil {
						logger.Debug("arp", zap.Any("ip", ip))
					} else {
						logger.Debug("runE", zap.Any("prefix", prefix))
						timeoutCh := tcpScanner.ScanPrefix(prefix)
						normalPrintfTCP(timeoutCh, tcpScanner.ResultCh)
					}
				} else {
					timeoutCh := tcpScanner.ScanMany([]netip.Addr{ip})
					normalPrintfTCP(timeoutCh, tcpScanner.ResultCh)
				}
			}
			return nil
		},
	}
)

func normalPrintfTCP(timeoutCh chan struct{}, resultCh chan *port.TCPResult) {
	for {
		select {
		case result := <-resultCh:
			fmt.Printf("%s\t%v\ttcp\topen\n", result.IP, result.Port)
		case <-timeoutCh:
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(portCmd)
	portCmd.Flags().StringArrayP("host", "h", []string{}, "host, domain or cidr to scan")
	portCmd.Flags().BoolP("all", "a", false, "to scan all localnet")
	portCmd.Flags().BoolP("udp", "u", false, "to scan udp")
	portCmd.Flags().BoolP("full", "f", false, "to scan by full tcp connect")
	portCmd.Flags().StringArrayP("port", "p", []string{}, "port to scan")
}
