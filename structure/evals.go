package structure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/agent-ecosystem/skill-validator/types"
	"github.com/agent-ecosystem/skill-validator/util"
)

// evalsFile is where the Agent Skills docs place a skill's eval test cases.
const evalsFile = "evals/evals.json"

type evalsDoc struct {
	SkillName *string           `json:"skill_name"`
	Evals     []json.RawMessage `json:"evals"`
}

type evalCase struct {
	ID             any       `json:"id"`
	Prompt         *string   `json:"prompt"`
	ExpectedOutput *string   `json:"expected_output"`
	Files          *[]string `json:"files"`
	Assertions     *[]string `json:"assertions"`
}

// CheckEvals validates evals/evals.json against the format described at
// agentskills.io (skill-creation/evaluating-skills). Evals are how a skill's
// value is measured: agent-vendor guidance and empirical studies agree that a
// skill should be compared against a no-skill baseline before adoption.
// Without an evals file, it adds an informational note.
func CheckEvals(dir, skillName string) []types.Result {
	ctx := types.ResultContext{Category: "Evals", File: evalsFile}
	path := filepath.Join(dir, filepath.FromSlash(evalsFile))

	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return []types.Result{types.ResultContext{Category: "Evals"}.Info("no " + evalsFile + " — " +
			"add a few realistic test prompts and compare runs with and without the skill " +
			"to confirm it improves results (see agentskills.io/skill-creation/evaluating-skills)")}
	}

	data, err := util.SafeReadFile(dir, path)
	if err != nil {
		return []types.Result{ctx.Errorf("could not read %s: %v", evalsFile, err)}
	}

	var doc evalsDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return []types.Result{ctx.Errorf("%s is not valid: %v", evalsFile, err)}
	}

	var results []types.Result
	if doc.SkillName == nil {
		results = append(results, ctx.Warn(`missing "skill_name"`))
	} else if skillName != "" && *doc.SkillName != skillName {
		results = append(results, ctx.Warnf(`"skill_name" is %q but the skill's name is %q`, *doc.SkillName, skillName))
	}
	if len(doc.Evals) == 0 {
		results = append(results, ctx.Error(`"evals" must be a non-empty array of test cases`))
		return results
	}

	seenIDs := map[string]bool{}
	valid := 0
	for i, raw := range doc.Evals {
		label := fmt.Sprintf("evals[%d]", i)
		var ec evalCase
		if err := json.Unmarshal(raw, &ec); err != nil {
			results = append(results, ctx.Errorf("%s is not a valid test case: %v", label, err))
			continue
		}
		caseOK := true
		if ec.ID == nil {
			results = append(results, ctx.Warnf(`%s is missing "id"`, label))
		} else {
			id := fmt.Sprint(ec.ID)
			if seenIDs[id] {
				results = append(results, ctx.Warnf(`%s has duplicate id %s`, label, id))
			}
			seenIDs[id] = true
		}
		if ec.Prompt == nil || strings.TrimSpace(*ec.Prompt) == "" {
			results = append(results, ctx.Errorf(`%s is missing "prompt"`, label))
			caseOK = false
		}
		if ec.ExpectedOutput == nil || strings.TrimSpace(*ec.ExpectedOutput) == "" {
			results = append(results, ctx.Warnf(`%s is missing "expected_output" — describe what success looks like`, label))
		}
		if ec.Files != nil {
			for _, f := range *ec.Files {
				if msg := checkEvalFile(dir, f); msg != "" {
					results = append(results, ctx.Errorf("%s: %s", label, msg))
					caseOK = false
				}
			}
		}
		if ec.Assertions != nil {
			for j, a := range *ec.Assertions {
				if strings.TrimSpace(a) == "" {
					results = append(results, ctx.Warnf("%s: assertions[%d] is empty", label, j))
				}
			}
		}
		if caseOK {
			valid++
		}
	}

	if valid > 0 {
		results = append(results, ctx.Passf("%d eval test case%s", valid, util.PluralS(valid)))
	}
	return results
}

// checkEvalFile reports a problem with a test case's input file path, or ""
// if the file exists inside the skill directory.
func checkEvalFile(dir, rel string) string {
	if rel == "" {
		return "empty file path in \"files\""
	}
	if filepath.IsAbs(rel) || strings.Contains(rel, `\`) {
		return fmt.Sprintf("file path %q must be relative to the skill directory and use forward slashes", rel)
	}
	resolved := filepath.Clean(filepath.Join(dir, filepath.FromSlash(rel)))
	if !strings.HasPrefix(resolved, filepath.Clean(dir)+string(filepath.Separator)) {
		return fmt.Sprintf("file path %q escapes the skill directory", rel)
	}
	if _, err := os.Stat(resolved); err != nil {
		return fmt.Sprintf("file %q not found", rel)
	}
	if inside, err := util.ResolvesWithin(dir, resolved); err != nil || !inside {
		return fmt.Sprintf("file %q resolves outside the skill directory", rel)
	}
	return ""
}
