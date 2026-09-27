package structure

import (
	"testing"

	"github.com/agent-ecosystem/skill-validator/types"
)

func TestCheckEvals(t *testing.T) {
	t.Run("no evals file", func(t *testing.T) {
		dir := t.TempDir()
		results := CheckEvals(dir, "my-skill")
		requireResultContaining(t, results, types.Info, "no evals/evals.json")
	})

	t.Run("valid evals", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "evals/files/input.csv", "a,b\n1,2\n")
		writeFile(t, dir, "evals/evals.json", `{
  "skill_name": "my-skill",
  "evals": [
    {"id": 1, "prompt": "Summarize input.csv", "expected_output": "A summary",
     "files": ["evals/files/input.csv"], "assertions": ["Mentions both columns"]},
    {"id": 2, "prompt": "Chart it", "expected_output": "A chart"}
  ]
}`)
		results := CheckEvals(dir, "my-skill")
		requireResult(t, results, types.Pass, "2 eval test cases")
		requireNoResultContaining(t, results, types.Error, "")
		requireNoResultContaining(t, results, types.Warning, "")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "evals/evals.json", `{"evals": [`)
		results := CheckEvals(dir, "my-skill")
		requireResultContaining(t, results, types.Error, "is not valid")
	})

	t.Run("empty evals array", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "evals/evals.json", `{"skill_name": "my-skill", "evals": []}`)
		results := CheckEvals(dir, "my-skill")
		requireResultContaining(t, results, types.Error, "non-empty array")
	})

	t.Run("case problems", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "evals/evals.json", `{
  "skill_name": "other-skill",
  "evals": [
    {"id": 1, "prompt": "", "expected_output": "x"},
    {"id": 1, "prompt": "p", "files": ["evals/files/missing.txt", "../outside.txt"]}
  ]
}`)
		results := CheckEvals(dir, "my-skill")
		requireResultContaining(t, results, types.Warning, `"skill_name" is "other-skill"`)
		requireResultContaining(t, results, types.Error, `evals[0] is missing "prompt"`)
		requireResultContaining(t, results, types.Warning, "duplicate id 1")
		requireResultContaining(t, results, types.Warning, `evals[1] is missing "expected_output"`)
		requireResultContaining(t, results, types.Error, `file "evals/files/missing.txt" not found`)
		requireResultContaining(t, results, types.Error, "escapes the skill directory")
	})
}

func TestValidate_ConventionDirs(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, dir, "---\nname: "+dirName(dir)+"\ndescription: Use when testing.\n---\n# Body\n")
	writeFile(t, dir, "evals/evals.json", `{"skill_name": "`+dirName(dir)+`", "evals": [{"id": 1, "prompt": "p", "expected_output": "o"}]}`)
	writeFile(t, dir, "agents/openai.yaml", "interface:\n  display_name: Test\n")

	report := Validate(dir, Options{})
	requireNoResultContaining(t, report.Results, types.Warning, "unknown directory")
	for _, tc := range report.OtherTokenCounts {
		t.Errorf("convention dir file counted as other tokens: %s", tc.File)
	}
	requireResult(t, report.Results, types.Pass, "1 eval test case")
}

func TestValidate_AllowDirsEvalsSkipsSchema(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, dir, "---\nname: "+dirName(dir)+"\ndescription: Use when testing.\n---\n# Body\n")
	writeFile(t, dir, "evals/evals.json", `{"tests": []}`)

	report := Validate(dir, Options{AllowDirs: []string{"evals"}})
	for _, r := range report.Results {
		if r.Category == "Evals" {
			t.Errorf("expected evals schema check to be skipped, got: %s", r.Message)
		}
	}
}
