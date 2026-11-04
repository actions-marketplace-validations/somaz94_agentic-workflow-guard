package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FuzzScan feeds the scan what a fork could commit. It holds only the one property
// that matters on hostile input: the scan returns, and quickly, because these inputs
// are small and the time limit is a backstop rather than the plan. A stack overflow
// or a panic fails the run by itself.
func FuzzScan(f *testing.F) {
	for _, dir := range []string{"clean", "risky", "indirect"} {
		files, err := filepath.Glob(filepath.Join("..", "..", "testdata", dir, ".github", "workflows", "*.yml"))
		if err != nil {
			f.Fatal(err)
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(data, []byte("runs:\n  using: composite\n  steps:\n    - uses: ./act\n"))
		}
	}
	f.Add([]byte("on: issues\njobs:\n  a:\n    strategy: {matrix: {x: ['${{ matrix.x }}']}}\n    env: {A: '${{ env.A }}'}\n    outputs: {x: '${{ needs.a.outputs.x }}'}\n    needs: a\n    steps:\n      - id: s\n        run: claude -p \"$A\" > f.txt\n      - uses: ./act\n        with: {p: '${{ steps.s.outputs.x }}'}\n      - uses: actions/ai-inference@v2\n        with: {prompt: '${{ matrix.x }} ${{ needs.a.outputs.x }} ${{ env.A }} ${{ toJSON(steps) }}'}\n"),
		[]byte("inputs: {p: {default: '${{ inputs.p }}'}}\nruns:\n  using: composite\n  steps:\n    - uses: ./act\n    - uses: openai/codex-action@v1\n      with: {allow-users: '${{ inputs.p }}'}\n"))
	r := reg(f)
	f.Fuzz(func(t *testing.T, wf, action []byte) {
		root := t.TempDir()
		write(t, root, ".github/workflows/w.yml", string(wf))
		write(t, root, "act/action.yml", string(action))
		start := time.Now()
		// An error is a correct outcome: it is how a scan refuses a hostile tree.
		_, _ = Scan(r, root, nil)
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("scan took %s", d)
		}
	})
}
