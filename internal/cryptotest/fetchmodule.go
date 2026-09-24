// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptotest

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"testing"
)

// FetchModule fetches the module at the given version and returns the directory
// containing its source tree.
func FetchModule(t *testing.T, module, version string) string {
	t.Logf("fetching %s@%s\n", module, version)

	cmd := exec.Command("go", "mod", "download", "-json", module+"@"+version)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to download %s@%s: %s\nstdout:\n%s\nstderr:\n%s\n", module, version, err, output, stderr.Bytes())
	}
	if stderr.Len() > 0 {
		t.Logf("go mod download stderr:\n%s", stderr.Bytes())
	}
	var j struct {
		Dir string
	}
	if err := json.Unmarshal(output, &j); err != nil {
		t.Fatalf("failed to parse 'go mod download': %s\nstdout:\n%s\nstderr:\n%s\n", err, output, stderr.Bytes())
	}

	return j.Dir
}
