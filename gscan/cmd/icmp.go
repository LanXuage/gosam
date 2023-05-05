package cmd

import (
	"fmt"
	"gscan/common"
	"gscan/icmp"
	"net/netip"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	icmpScanner = icmp.New()
	icmpCmd     = &cobra.Command{
		Use:   "icmp",
		Short: "ICMP Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := common.GetLogger()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			icmpScanner.Timeout = time.Second * time.Duration(timeout)
			host, _ := cmd.Flags().GetString("host")
			logger.Debug("runE", zap.Any("host", host))
			if host == "" {
				cmd.Help()
			} else if _, err := netip.ParseAddr(host); err != nil {
				if prefix, err := netip.ParsePrefix(host); err == nil {
					logger.Debug("runE", zap.Any("prefix", prefix))
					timeoutCh := icmpScanner.ScanListByPrefix(prefix)
					icmpPrintf(timeoutCh, icmpScanner.ResultCh)
				}
			} else if ip, err := netip.ParseAddr(host); err == nil {
				logger.Debug("icmp", zap.Any("ip", ip))
				timeoutCh := icmpScanner.ScanOne(ip)
				icmpPrintf(timeoutCh, icmpScanner.ResultCh)
			}
			return nil
		},
	}
)

func icmpPrintf(timeoutCh chan struct{}, resultCh chan *icmp.ICMPScanResult) {
	for {
		select {
		case result := <-icmpScanner.ResultCh:
			if result.IsActive {
				fmt.Printf("%s is Active\n", result.IP)
			} else {
				fmt.Printf("%s is InActive\n", result.IP)
			}
		case <-timeoutCh:
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(icmpCmd)
	icmpCmd.Flags().StringP("host", "h", "", "host, domain or cidr to scan")
	icmpCmd.Flags().StringP("file", "f", "", "host, domain and cidr")
	// icmpCmd.Flags().StringArrayP("hosts", "hh", ";;", "scan hosts")
}
