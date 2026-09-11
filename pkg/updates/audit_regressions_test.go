//go:build auditregression

package updates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditReplaceMissingSourceDeletesDestination(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(dst, []byte(`{"valid":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := replaceFile(filepath.Join(dir, "missing.tmp"), dst)
	if err == nil {
		t.Fatal("expected missing-source failure")
	}
	data, readErr := os.ReadFile(dst)
	if readErr != nil || string(data) != `{"valid":true}` {
		t.Fatalf("UA-05: failed replacement destroyed destination: %v", readErr)
	}

}
