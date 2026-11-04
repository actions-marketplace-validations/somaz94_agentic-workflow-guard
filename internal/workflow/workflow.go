// Package workflow loads a GitHub Actions workflow file, keeping line numbers.
package workflow

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ErrTooLarge reports a file whose aliases expand past what a scan will hold.
var ErrTooLarge = errors.New("file expands to too much text through its YAML aliases")

// maxExpanded bounds a file once its aliases are counted, because each alias is
// rendered or scanned in full and a short file can name a large anchor many times.
const maxExpanded = 16 << 20

// Permissions is a resolved `permissions:` block.
type Permissions struct {
	// Set is false when the block is absent, so the repository default applies.
	Set bool
	// Writes lists the scopes granted write access. `write-all` is "*".
	Writes []string
}

// Input is one `with:` or `env:` entry.
type Input struct {
	Value string
	Line  int
}

// Step is one job step.
type Step struct {
	ID   string
	Name string
	Uses string
	Run  string
	If   string
	Line int
	With map[string]Input
	Env  map[string]Input
	// ContinueOnError is true when the step failing does not stop the job.
	ContinueOnError bool
}

// Job is one job. A job that calls a reusable workflow has Uses and no steps.
type Job struct {
	Name        string
	If          string
	Needs       []string
	Uses        string
	With        map[string]Input
	Outputs     map[string]Input
	Strategy    map[string]Input
	Permissions Permissions
	Env         map[string]Input
	Steps       []Step
	Line        int
}

// Workflow is one parsed file.
type Workflow struct {
	// Triggers maps each event to its `types:`, empty when none are listed.
	Triggers map[string][]string
	// CallInputs maps each `workflow_call` input to its default.
	CallInputs  map[string]Input
	Permissions Permissions
	Env         map[string]Input
	Jobs        []*Job
}

// Action is a parsed `action.yml`. Only a composite action has steps.
type Action struct {
	// Inputs maps each input to its default.
	Inputs map[string]Input
	Steps  []Step
}

// JobByName finds a job, nil when absent. Expressions match job names without
// regard to case.
func (w *Workflow) JobByName(name string) *Job {
	for _, j := range w.Jobs {
		if strings.EqualFold(j.Name, name) {
			return j
		}
	}
	return nil
}

// Parse reads the first YAML document of a workflow file.
func Parse(data []byte) (*Workflow, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a workflow: top level is not a mapping")
	}
	if expanded(&doc, map[*yaml.Node]int64{}) > maxExpanded {
		return nil, ErrTooLarge
	}
	root := doc.Content[0]
	w := &Workflow{
		Triggers:    triggers(get(root, "on")),
		CallInputs:  defaults(get(get(get(root, "on"), "workflow_call"), "inputs")),
		Permissions: permissions(get(root, "permissions")),
		Env:         inputs(get(root, "env")),
	}
	jobs := get(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return w, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		if j := job(jobs.Content[i], deref(jobs.Content[i+1])); j != nil {
			w.Jobs = append(w.Jobs, j)
		}
	}
	return w, nil
}

// expanded sums the text under a node with aliases counted each time they appear,
// plus an overhead per node, because an anchor of empty strings still costs a lot
// to render. A node seen on the way down counts as nothing, which ends a
// self-reference.
func expanded(n *yaml.Node, memo map[*yaml.Node]int64) int64 {
	if v, ok := memo[n]; ok {
		return v
	}
	memo[n] = 0
	size := int64(len(n.Value)) + 32
	if n.Alias != nil {
		size += expanded(n.Alias, memo)
	}
	for _, c := range n.Content {
		if size += expanded(c, memo); size > maxExpanded {
			break
		}
	}
	memo[n] = size
	return size
}

// ParseAction reads an `action.yml`.
func ParseAction(data []byte) (*Action, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not an action: top level is not a mapping")
	}
	if expanded(&doc, map[*yaml.Node]int64{}) > maxExpanded {
		return nil, ErrTooLarge
	}
	root := doc.Content[0]
	return &Action{Inputs: defaults(get(root, "inputs")), Steps: parseSteps(get(get(root, "runs"), "steps"))}, nil
}

func job(key, n *yaml.Node) *Job {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return &Job{
		Name:        key.Value,
		If:          scalar(get(n, "if")),
		Needs:       list(get(n, "needs")),
		Uses:        scalar(get(n, "uses")),
		With:        lowerKeys(inputs(get(n, "with"))),
		Outputs:     inputs(get(n, "outputs")),
		Strategy:    inputs(get(n, "strategy")),
		Permissions: permissions(get(n, "permissions")),
		Env:         inputs(get(n, "env")),
		Steps:       parseSteps(get(n, "steps")),
		Line:        key.Line,
	}
}

func parseSteps(n *yaml.Node) []Step {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []Step
	for _, s := range n.Content {
		s = deref(s)
		if s.Kind != yaml.MappingNode {
			continue
		}
		coe := scalar(get(s, "continue-on-error"))
		out = append(out, Step{
			ID:              scalar(get(s, "id")),
			Name:            scalar(get(s, "name")),
			Uses:            scalar(get(s, "uses")),
			Run:             scalar(get(s, "run")),
			If:              scalar(get(s, "if")),
			Line:            s.Line,
			With:            lowerKeys(inputs(get(s, "with"))),
			Env:             inputs(get(s, "env")),
			ContinueOnError: coe != "" && coe != "false",
		})
	}
	return out
}

// get resolves one mapping key, following aliases. YAML 1.1 readers turn a bare
// `on:` into a boolean key, but this decoder keeps the literal text.
func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return deref(n.Content[i+1])
		}
	}
	return nil
}

func deref(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode {
		return n.Alias
	}
	return n
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func list(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}
	}
	var out []string
	if n.Kind == yaml.SequenceNode {
		for _, c := range n.Content {
			if c = deref(c); c.Kind == yaml.ScalarNode {
				out = append(out, c.Value)
			}
		}
	}
	return out
}

func triggers(n *yaml.Node) map[string][]string {
	out := map[string][]string{}
	if n == nil {
		return out
	}
	switch n.Kind {
	case yaml.ScalarNode:
		out[n.Value] = nil
	case yaml.SequenceNode:
		for _, e := range list(n) {
			out[e] = nil
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			out[n.Content[i].Value] = list(get(deref(n.Content[i+1]), "types"))
		}
	}
	return out
}

func permissions(n *yaml.Node) Permissions {
	if n == nil {
		return Permissions{}
	}
	p := Permissions{Set: true}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value == "write-all" {
			p.Writes = []string{"*"}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if deref(n.Content[i+1]).Value == "write" {
				p.Writes = append(p.Writes, n.Content[i].Value)
			}
		}
		sort.Strings(p.Writes)
	}
	return p
}

// lowerKeys normalizes `with:` names, which the runner matches without regard to
// case. `env:` names keep theirs, because on Linux they are case-sensitive.
func lowerKeys(in map[string]Input) map[string]Input {
	if in == nil {
		return nil
	}
	out := make(map[string]Input, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
}

// defaults reads an `inputs:` declaration, keeping each input's default.
func defaults(n *yaml.Node) map[string]Input {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := make(map[string]Input, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		out[k.Value] = Input{Value: scalar(get(deref(n.Content[i+1]), "default")), Line: k.Line}
	}
	return out
}

// inputs flattens a mapping. A non-scalar value keeps its source text so a
// reference nested inside it is still visible to a scan.
func inputs(n *yaml.Node) map[string]Input {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := make(map[string]Input, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], deref(n.Content[i+1])
		val := v.Value
		if v.Kind != yaml.ScalarNode {
			if b, err := yaml.Marshal(v); err == nil {
				val = string(b)
			}
		}
		out[k.Value] = Input{Value: val, Line: k.Line}
	}
	return out
}
