package deps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePackageLockFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	content := `{
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/react": {"version": "19.1.0"},
    "node_modules/glob": {"version": "10.4.5"}
  },
  "dependencies": {
    "react": {"version": "19.1.0"},
    "glob": {"version": "10.4.5"}
  }
}`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	inv, err := parsePackageLockFile(path)
	require.NoError(t, err)
	assert.Equal(t, "19.1.0", inv.DirectVersions["react"])
	assert.Contains(t, inv.AllVersions["glob"], "10.4.5")
}

func TestParsePnpmLockFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pnpm-lock.yaml")
	content := `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      vue:
        version: 3.5.12
packages:
  vue@3.5.12: {}
  hookable@5.5.3: {}
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	inv, err := parsePnpmLockFile(path)
	require.NoError(t, err)
	assert.Equal(t, "3.5.12", inv.DirectVersions["vue"])
	assert.Contains(t, inv.AllVersions["hookable"], "5.5.3")
}

func TestParseYarnLockFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yarn.lock")
	content := `react@^19.1.0:
  version "19.1.0"

"@scope/pkg@^1.2.0":
  version "1.2.3"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	inv, err := parseYarnLockFile(path)
	require.NoError(t, err)
	assert.Contains(t, inv.AllVersions["react"], "19.1.0")
	assert.Contains(t, inv.AllVersions["@scope/pkg"], "1.2.3")
}
