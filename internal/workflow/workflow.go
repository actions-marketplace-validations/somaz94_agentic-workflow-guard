// Package workflow loads a GitHub Actions workflow file, keeping line numbers.
package workflow

import (
	"fmt"
	"sort"

	"go.yaml.in/yaml/v3"
)

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
}

// Job is one job. A job that calls a reusable workflow has no steps.
type Job struct {
	Name        string
	If          string
	Needs       []string
	Permissions Permissions
	Env         map[string]Input
	Steps       []Step
	Line        int
}

// Workflow is one parsed file.
type Workflow struct {
	// Triggers maps each event to its `types:`, empty when none are listed.
	Triggers    map[string][]string
	Permissions Permissions
	Env         map[string]Input
	Jobs        []*Job
}

// JobByName finds a job, nil when absent.
func (w *Workflow) JobByName(name string) *Job {
	for _, j := range w.Jobs {
		if j.Name == name {
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
	root := doc.Content[0]
	w := &Workflow{
		Triggers:    triggers(get(root, "on")),
		Permissions: permissions(get(root, "permissions")),
		Env:         inputs(get(root, "env")),
	}
	jobs := get(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return w, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		if j := job(jobs.Content[i], jobs.Content[i+1]); j != nil {
			w.Jobs = append(w.Jobs, j)
		}
	}
	return w, nil
}

func job(key, n *yaml.Node) *Job {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	j := &Job{
		Name:        key.Value,
		If:          scalar(get(n, "if")),
		Needs:       list(get(n, "needs")),
		Permissions: permissions(get(n, "permissions")),
		Env:         inputs(get(n, "env")),
		Line:        key.Line,
	}
	steps := get(n, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return j
	}
	for _, s := range steps.Content {
		if s.Kind != yaml.MappingNode {
			continue
		}
		j.Steps = append(j.Steps, Step{
			ID:   scalar(get(s, "id")),
			Name: scalar(get(s, "name")),
			Uses: scalar(get(s, "uses")),
			Run:  scalar(get(s, "run")),
			If:   scalar(get(s, "if")),
			Line: s.Line,
			With: inputs(get(s, "with")),
			Env:  inputs(get(s, "env")),
		})
	}
	return j
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
			if c.Kind == yaml.ScalarNode {
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
