package cmd

import (
	"fmt"
	"gscan/arp"
	"gscan/common"
	"net/netip"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	arpScanner = arp.GetARPScanner()
	arpCmd     = &cobra.Command{
		Use:   "arp",
		Short: "ARP Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := common.GetLogger()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			arpScanner.Timeout = time.Second * time.Duration(timeout)
			host, _ := cmd.Flags().GetString("host")
			logger.Debug("runE", zap.Any("host", host))
			if host == "" {
				all, _ := cmd.Flags().GetBool("all")
				if all {
					timeoutCh := arpScanner.ScanLocalNet()
					normalPrintf(timeoutCh, arpScanner.ResultCh)
				} else {
					cmd.Help()
				}
			} else if ip, err := netip.ParseAddr(host); err != nil {
				if prefix, err := netip.ParsePrefix(host); err != nil {
					logger.Debug("arp", zap.Any("ip", ip))
				} else {
					logger.Debug("runE", zap.Any("prefix", prefix))
					timeoutCh := arpScanner.ScanPrefix(prefix)
					normalPrintf(timeoutCh, arpScanner.ResultCh)
				}
			} else {
				result := arpScanner.ScanOne(ip)
				if result != nil {
					fmt.Printf("%s\t%v\t%s\n", result.IP, result.Mac, result.Vendor)
				} else {
					fmt.Printf("no result(timeout %ds)\n", timeout)
				}
			}
			return nil
		},
	}
)

func normalPrintf(timeoutCh chan struct{}, resultCh chan *arp.ARPScanResult) {
	for {
		select {
		case result := <-arpScanner.ResultCh:
			fmt.Printf("%s\t%v\t%s\n", result.IP, result.Mac, result.Vendor)
		case <-timeoutCh:
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(arpCmd)
	arpCmd.Flags().StringP("host", "h", "", "host, domain or cidr to scan")
	arpCmd.Flags().BoolP("all", "a", false, "to scan all localnet")
}
