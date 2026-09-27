// Package security scans skill packages for patterns associated with the
// vulnerability classes found in public skill marketplaces: prompt
// injection, data exfiltration, privilege escalation, and supply-chain risk
// (see "Agent Skills in the Wild", arXiv:2601.10338, which found at least one
// such pattern in 26.1% of 31,132 marketplace skills).
//
// The rules are deliberately narrow, high-precision signatures. A clean
// result is not proof of safety; a finding is a prompt for human review.
//
// # Stability
//
// This package is EXPERIMENTAL. Its API and rule set may change in minor
// releases without a major version bump. See the project README for the
// full stability policy.
package security

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-ecosystem/skill-validator/skill"
	"github.com/agent-ecosystem/skill-validator/types"
	"github.com/agent-ecosystem/skill-validator/util"
)

// rule is one line-level signature.
type rule struct {
	pattern *regexp.Regexp
	level   types.Level
	message string
	// markdownOnly limits the rule to .md files (instructions the agent
	// reads, as opposed to code it runs).
	markdownOnly bool
}

var rules = []rule{
	// Prompt injection: text that tries to override the agent's
	// instructions or hide actions from the user.
	{
		pattern:      regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|rules|directions)\b`),
		level:        types.Warning,
		message:      "text that tells the agent to ignore its prior instructions — a prompt-injection pattern",
		markdownOnly: true,
	},
	{
		pattern:      regexp.MustCompile(`(?i)\b(override|bypass|disable)\s+(the\s+|your\s+|any\s+)?(system prompt|safety (rules|guidelines|checks)|guardrails)\b`),
		level:        types.Warning,
		message:      "text that tells the agent to override its system prompt or safety rules — a prompt-injection pattern",
		markdownOnly: true,
	},
	{
		pattern:      regexp.MustCompile(`(?i)\b(without|never|don't|do not)\s+(telling|informing|notifying|asking|tell|inform|notify|mention(ing)? (this|it) to)\s+the user\b`),
		level:        types.Warning,
		message:      "text that tells the agent to act without the user's knowledge — review whether this skill conceals actions",
		markdownOnly: true,
	},

	// Supply chain: executing code fetched at run time.
	{
		pattern: regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`),
		level:   types.Warning,
		message: "downloads a script and pipes it into a shell — the code that runs is not in the skill and can change at any time; bundle the script or pin and verify it",
	},
	{
		pattern: regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b`),
		level:   types.Warning,
		message: "downloads code and pipes it into an interpreter — the code that runs is not in the skill and can change at any time; bundle it or pin and verify it",
	},
	{
		pattern: regexp.MustCompile(`(?i)\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b[^\n]*\|\s*(iex|invoke-expression)\b|\b(iex|invoke-expression)\b[^\n]*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b`),
		level:   types.Warning,
		message: "downloads PowerShell code and executes it — the code that runs is not in the skill and can change at any time",
	},
	{
		pattern: regexp.MustCompile(`(?i)base64\s+(-d|--decode)\b[^\n]*\|\s*(ba|z)?sh\b|\b(eval|exec)\s*\(\s*(base64\.b64decode|atob|Buffer\.from)\s*\(`),
		level:   types.Warning,
		message: "decodes and executes an encoded payload — obfuscated code hides what the skill does from reviewers",
	},

	// Data exfiltration: credential stores and environment dumps.
	{
		pattern: regexp.MustCompile(`(?i)(~|\$HOME|\$\{HOME\}|%USERPROFILE%)[/\\]\.(ssh|aws|gnupg|kube|docker|netrc)\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|/etc/shadow\b|\bsecurity\s+find-(generic|internet)-password\b`),
		level:   types.Warning,
		message: "accesses a credential store (SSH keys, cloud or registry credentials, keychain) — confirm the skill needs it and that the data never leaves the machine",
	},
	{
		pattern: regexp.MustCompile(`(?i)\b(printenv|os\.environ|process\.env|\$env:)[^\n]*\b(curl|wget|requests\.(post|put)|fetch\(|http\.post|invoke-webrequest|invoke-restmethod)\b|\b(curl|wget)\b[^\n]*\$\((env|printenv)\)`),
		level:   types.Warning,
		message: "sends environment variables over the network — environments hold API keys and tokens",
	},

	// Secrets committed into the skill.
	{
		pattern: regexp.MustCompile(`-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----`),
		level:   types.Error,
		message: "contains a private key — remove it; anyone who installs the skill receives it",
	},
	{
		pattern: regexp.MustCompile(`\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|sk-ant-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20})\b`),
		level:   types.Error,
		message: "contains what looks like an access token — remove it and rotate the credential; skills are shared with everyone who installs them",
	},

	// Privilege escalation: weakening the host's safety controls.
	{
		pattern: regexp.MustCompile(`--dangerously-skip-permissions\b|\bdangerouslyDisableSandbox\b|\bbypassPermissions\b|--dangerously-bypass-approvals-and-sandbox\b`),
		level:   types.Warning,
		message: "disables the agent's permission checks or sandbox — a skill should work within the user's configured permissions",
	},
	{
		pattern: regexp.MustCompile(`\bchmod\s+(-R\s+)?(0?777|a\+rwx)\b`),
		level:   types.Warning,
		message: "makes files world-writable — grant the narrowest permissions that work",
	},
}

// invisibleChars matches zero-width and bidirectional-override characters,
// which can hide instructions from a human reviewer while the model still
// reads them. Zero-width joiners (used in emoji) are not included.
var invisibleChars = regexp.MustCompile(`[\x{200B}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]`)

// unrestrictedBash matches allowed-tools entries that pre-approve every
// shell command.
var unrestrictedBash = regexp.MustCompile(`^Bash(\(\*\)|\(\*:\*\))?$`)

// skippedDirs are not scanned: agents do not load them while using the
// skill, and eval fixtures may legitimately contain attack samples.
var skippedDirs = map[string]bool{"evals": true}

// Analyze scans every text file in the skill directory, plus the
// frontmatter's allowed-tools, and returns findings. s may be nil when
// SKILL.md could not be parsed; file content is still scanned.
func Analyze(dir string, s *skill.Skill) []types.Result {
	ctx := types.ResultContext{Category: "Security"}
	var results []types.Result

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != dir && (strings.HasPrefix(d.Name(), ".") || skippedDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		data, _, err := util.SafeReadFileN(dir, path, util.MaxSkillFileBytes)
		if err != nil || isBinary(data) {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		results = append(results, scanFile(ctx, filepath.ToSlash(rel), string(data))...)
		return nil
	})

	if s != nil && !s.Frontmatter.AllowedTools.IsEmpty() {
		for _, tool := range strings.FieldsFunc(s.Frontmatter.AllowedTools.Value, func(r rune) bool {
			return r == ' ' || r == ','
		}) {
			if unrestrictedBash.MatchString(tool) {
				results = append(results, types.ResultContext{Category: "Security", File: "SKILL.md"}.Infof(
					"allowed-tools pre-approves %q, which covers every shell command — scope it to the commands the skill runs (e.g. Bash(git:*))", tool))
				break
			}
		}
	}

	if len(results) == 0 {
		results = append(results, ctx.Pass("no known risky patterns found"))
	}
	return results
}

func scanFile(ctx types.ResultContext, rel, text string) []types.Result {
	var results []types.Result
	isMarkdown := strings.EqualFold(filepath.Ext(rel), ".md")
	for i, line := range strings.Split(text, "\n") {
		lineNo := i + 1
		for _, r := range rules {
			if r.markdownOnly && !isMarkdown {
				continue
			}
			if !r.pattern.MatchString(line) {
				continue
			}
			if r.level == types.Error {
				results = append(results, ctx.ErrorAtLinef(rel, lineNo, "%s", r.message))
			} else {
				results = append(results, ctx.WarnAtLinef(rel, lineNo, "%s", r.message))
			}
		}
		if invisibleChars.MatchString(line) {
			results = append(results, ctx.WarnAtLinef(rel, lineNo,
				"contains invisible zero-width or text-direction characters — they can hide instructions from reviewers while the agent still reads them"))
		}
	}
	return results
}

// isBinary reports whether data looks like a binary file.
func isBinary(data []byte) bool {
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}
