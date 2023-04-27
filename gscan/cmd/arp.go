package cmd

import (
	"fmt"
	"gscan/arp"
	"gscan/common"
	"net/netip"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	arpScanner = arp.GetARPScanner()
	arpCmd     = &cobra.Command{
		Use:   "arp",
		Short: "Arp Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := common.GetLogger()
			target, _ := cmd.Flags().GetString("target")
			logger.Debug(target)
			if ip, err := netip.ParseAddr(target); err != nil {
				logger.Debug("arp", zap.Any("ip", ip))
			} else {
				result := arpScanner.ScanOne(ip)
				if result != nil {
					fmt.Println(common.ToJSON(result))
				} else {
					fmt.Println("no result(timeout 5s)")
				}
			}
			return nil
		},
	}
)

func init() {
	rootCmd.AddCommand(arpCmd)
	arpCmd.Flags().StringP("target", "t", "", "target to scan")
}
