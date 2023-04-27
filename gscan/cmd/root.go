package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	debug   bool
	rootCmd = &cobra.Command{
		Use:   "gscan",
		Short: "A Scanner. ",
		Long: `Gscan
   ____  ______ ____ _____    ____  
  / ___\/  ___// ___\\__  \  /    \ 
 / /_/  >___ \\  \___ / __ \|   |  \
 \___  /____  >\___  >____  /___|  /
/_____/     \/     \/     \/     \/ 
https://github.com/LanXuage/gosam

A Scanner. `,
		Version: "0.1.0",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				os.Setenv("GSCAN_LOG_LEVEL", "development")
			} else {
				os.Setenv("GSCAN_LOG_LEVEL", "production")
			}
		},
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "set debug log level")
	rootCmd.PersistentFlags().BoolP("help", "", false, "help for this command")
}
