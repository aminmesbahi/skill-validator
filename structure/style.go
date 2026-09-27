package structure

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-ecosystem/skill-validator/types"
	"github.com/agent-ecosystem/skill-validator/util"
)

// tocLineThreshold is the length above which Anthropic's skill authoring
// guidance asks reference files to open with a table of contents, so an
// agent that previews only the top of the file still sees its full scope.
const tocLineThreshold = 100

// tocSearchLines is how far into a file a table of contents may start.
const tocSearchLines = 30

var (
	tocHeadingPattern = regexp.MustCompile(`(?im)^#{1,6}\s+(table of )?contents\b`)
	anchorLinkPattern = regexp.MustCompile(`\]\(#[^)]+\)`)
)

// CheckReferenceTOC flags markdown files in references/ longer than
// tocLineThreshold lines that do not start with a table of contents.
func CheckReferenceTOC(dir string) []types.Result {
	var results []types.Result
	refsDir := filepath.Join(dir, "references")
	_ = filepath.WalkDir(refsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != refsDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !strings.EqualFold(filepath.Ext(d.Name()), ".md") {
			return nil
		}
		data, err := util.SafeReadFile(dir, path)
		if err != nil {
			return nil // unreadable and oversized files are reported by other checks
		}
		text := string(data)
		lines := strings.Count(text, "\n") + 1
		if lines <= tocLineThreshold || hasTableOfContents(text) {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		results = append(results, types.ResultContext{Category: "Structure", File: rel}.Infof(
			"%s is %d lines with no table of contents — agents often preview only the top of long files; "+
				"list its sections near the top so the full scope is visible", rel, lines))
		return nil
	})
	return results
}

// hasTableOfContents reports whether the opening lines of a markdown file
// contain a "Contents" heading or a list of in-page anchor links.
func hasTableOfContents(text string) bool {
	lines := strings.SplitN(text, "\n", tocSearchLines+1)
	if len(lines) > tocSearchLines {
		lines = lines[:tocSearchLines]
	}
	head := strings.Join(lines, "\n")
	return tocHeadingPattern.MatchString(head) || len(anchorLinkPattern.FindAllString(head, -1)) >= 3
}

var (
	// A path into the skill written with Windows separators, e.g.
	// scripts\helper.py or references\guide.md.
	backslashPathPattern = regexp.MustCompile(`(?i)\b(?:scripts|references|assets|reference|evals)\\[\w.\-\\]+`)
	// A markdown link target containing a backslash.
	backslashLinkPattern = regexp.MustCompile(`\]\(([^)\s]*\\[^)\s]*)\)`)
)

// CheckPathSeparators flags file paths in SKILL.md written with Windows
// backslashes. Agents run on Unix-like systems where those paths fail.
func CheckPathSeparators(body string) []types.Result {
	ctx := types.ResultContext{Category: "Structure", File: "SKILL.md"}
	seen := map[string]bool{}
	var results []types.Result
	add := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		results = append(results, ctx.Warnf(
			"path %s uses backslashes — use forward slashes (%s); Windows-style paths fail on Unix systems",
			p, strings.ReplaceAll(p, `\`, "/")))
	}
	for _, m := range backslashLinkPattern.FindAllStringSubmatch(body, -1) {
		add(m[1])
	}
	for _, m := range backslashPathPattern.FindAllString(body, -1) {
		add(m)
	}
	return results
}
