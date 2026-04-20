package main

import (
	"os"

	"github.com/cen-ngc5139/shepherd/internal/config"
	"github.com/cen-ngc5139/shepherd/internal/log"
	"github.com/cen-ngc5139/shepherd/internal/run"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

func main() {
	// 日志
	klog.InitFlags(nil)
	log.InitLogger("./log/", 100, 5, 30)
	defer klog.Flush()

	// 主程序
	var rootCmd = &cobra.Command{
		Use:   "shepherd",
		Short: "A Linux eBPF-based tool for detecting and analyzing noisy neighbor problems in process scheduling",
		Run: func(cmd *cobra.Command, args []string) {
			run.Run(config.Config)
		},
	}

	config.SetFlags(rootCmd.Flags())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
