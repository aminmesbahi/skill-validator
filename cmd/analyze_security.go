package cmd

import (
	"github.com/spf13/cobra"

	"github.com/agent-ecosystem/skill-validator/orchestrate"
	"github.com/agent-ecosystem/skill-validator/types"
)

var strictSecurity bool

var analyzeSecurityCmd = &cobra.Command{
	Use:   "security <path>",
	Short: "Scan for risky patterns (prompt injection, exfiltration, remote code, secrets)",
	Long: `Scans every text file in the skill for patterns associated with the
vulnerability classes found in public skill marketplaces: prompt injection,
credential access and data exfiltration, remote code execution, disabled
safety controls, committed secrets, and invisible characters.

The rules are narrow signatures. A clean result is not proof of safety;
a finding is a prompt for human review.`,
	Args: cobra.ExactArgs(1),
	RunE: runAnalyzeSecurity,
}

func init() {
	analyzeSecurityCmd.Flags().BoolVar(&strictSecurity, "strict", false, "treat warnings as errors (exit 1 instead of 2)")
	analyzeCmd.AddCommand(analyzeSecurityCmd)
}

func runAnalyzeSecurity(cmd *cobra.Command, args []string) error {
	_, mode, dirs, err := detectAndResolve(args)
	if err != nil {
		return err
	}

	eopts := exitOpts{strict: strictSecurity}
	switch mode {
	case types.SingleSkill:
		r := orchestrate.RunSecurityAnalysis(dirs[0])
		return outputReportWithExitOpts(r, false, eopts)
	case types.MultiSkill:
		mr := &types.MultiReport{}
		for _, dir := range dirs {
			r := orchestrate.RunSecurityAnalysis(dir)
			mr.Skills = append(mr.Skills, r)
			mr.Errors += r.Errors
			mr.Warnings += r.Warnings
		}
		return outputMultiReportWithExitOpts(mr, false, eopts)
	}
	return nil
}
