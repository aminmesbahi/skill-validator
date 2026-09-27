package cmd

import (
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze skill content, contamination, or security",
	Long:  "Parent command for content, contamination, and security analysis subcommands.",
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}
