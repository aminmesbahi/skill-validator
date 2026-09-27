package structure

import (
	"strings"
	"testing"

	"github.com/agent-ecosystem/skill-validator/types"
)

func TestCheckReferenceTOC(t *testing.T) {
	long := strings.Repeat("Some reference content.\n", 120)

	t.Run("long file without TOC", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "references/api.md", "# API\n\n"+long)
		results := CheckReferenceTOC(dir)
		requireResultContaining(t, results, types.Info, "references/api.md is 123 lines with no table of contents")
	})

	t.Run("contents heading", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "references/api.md", "# API\n\n## Contents\n- Auth\n- Methods\n\n"+long)
		if results := CheckReferenceTOC(dir); len(results) != 0 {
			t.Errorf("expected no findings, got %v", results)
		}
	})

	t.Run("anchor link list", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "references/api.md", "# API\n\n- [Auth](#auth)\n- [Methods](#methods)\n- [Errors](#errors)\n\n"+long)
		if results := CheckReferenceTOC(dir); len(results) != 0 {
			t.Errorf("expected no findings, got %v", results)
		}
	})

	t.Run("short file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "references/short.md", "# Short\n\nOnly a few lines.\n")
		if results := CheckReferenceTOC(dir); len(results) != 0 {
			t.Errorf("expected no findings, got %v", results)
		}
	})
}

func TestCheckPathSeparators(t *testing.T) {
	body := "Run `python scripts\\helper.py`.\nSee [guide](references\\guide.md).\nRegex: `\\d+` and a newline `\\n`.\n"
	results := CheckPathSeparators(body)
	requireResultContaining(t, results, types.Warning, `path scripts\helper.py uses backslashes`)
	requireResultContaining(t, results, types.Warning, `path references\guide.md uses backslashes`)
	if len(results) != 2 {
		t.Errorf("expected 2 findings, got %d: %v", len(results), results)
	}

	if results := CheckPathSeparators("Run `python scripts/helper.py`."); len(results) != 0 {
		t.Errorf("expected no findings for forward slashes, got %v", results)
	}
}

func TestCheckOrphanFiles_NestedReferences(t *testing.T) {
	dir := t.TempDir()
	body := "See [advanced](references/advanced.md).\n"
	writeFile(t, dir, "references/advanced.md", "For details see [details](details.md).\n")
	writeFile(t, dir, "references/details.md", "The actual information.\n")

	results := CheckOrphanFiles(dir, body, Options{})
	requireResultContaining(t, results, types.Info, "references/details.md is linked only from references/advanced.md")
	requireNoResultContaining(t, results, types.Info, "references/advanced.md is linked only")
}
