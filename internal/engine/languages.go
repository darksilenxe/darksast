package engine

import (
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/bash"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/ruby"
	"github.com/smacker/go-tree-sitter/rust"
	tsyaml "github.com/smacker/go-tree-sitter/yaml"
)

type languageSpec struct {
	key           string
	displayName   string
	language      *sitter.Language
	extensions    map[string]struct{}
	supportsTaint bool
}

var languageSpecs = map[string]languageSpec{
	"javascript": {
		key:           "javascript",
		displayName:   "JavaScript",
		language:      javascript.GetLanguage(),
		extensions:    map[string]struct{}{".js": {}, ".jsx": {}, ".ts": {}, ".tsx": {}, ".mjs": {}, ".cjs": {}},
		supportsTaint: true,
	},
	"python": {
		key:         "python",
		displayName: "Python",
		language:    python.GetLanguage(),
		extensions:  map[string]struct{}{".py": {}},
	},
	"go": {
		key:         "go",
		displayName: "Go",
		language:    golang.GetLanguage(),
		extensions:  map[string]struct{}{".go": {}},
	},
	"rust": {
		key:         "rust",
		displayName: "Rust",
		language:    rust.GetLanguage(),
		extensions:  map[string]struct{}{".rs": {}},
	},
	"java": {
		key:         "java",
		displayName: "Java",
		language:    java.GetLanguage(),
		extensions:  map[string]struct{}{".java": {}},
	},
	"php": {
		key:         "php",
		displayName: "PHP",
		language:    php.GetLanguage(),
		extensions:  map[string]struct{}{".php": {}},
	},
	"ruby": {
		key:         "ruby",
		displayName: "Ruby",
		language:    ruby.GetLanguage(),
		extensions:  map[string]struct{}{".rb": {}},
	},
	"csharp": {
		key:         "csharp",
		displayName: "C#",
		language:    csharp.GetLanguage(),
		extensions:  map[string]struct{}{".cs": {}},
	},
	"bash": {
		key:         "bash",
		displayName: "Bash",
		language:    bash.GetLanguage(),
		extensions:  map[string]struct{}{".sh": {}, ".bash": {}, ".zsh": {}},
	},
	"yaml": {
		key:         "yaml",
		displayName: "YAML",
		language:    tsyaml.GetLanguage(),
		extensions:  map[string]struct{}{".yaml": {}, ".yml": {}},
	},
}

func normalizeLanguageName(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "javascript", "js", "typescript", "ts", "jsx", "tsx", "mjs", "cjs":
		return "javascript"
	case "python", "py":
		return "python"
	case "go", "golang":
		return "go"
	case "rust", "rs":
		return "rust"
	case "java":
		return "java"
	case "php":
		return "php"
	case "ruby", "rb":
		return "ruby"
	case "c#", "csharp", "cs", "c-sharp":
		return "csharp"
	case "bash", "shell", "sh", "zsh":
		return "bash"
	case "yaml", "yml":
		return "yaml"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func languageSpecForName(value string) (languageSpec, error) {
	key := normalizeLanguageName(value)
	spec, ok := languageSpecs[key]
	if !ok {
		return languageSpec{}, fmt.Errorf("unsupported language %q", value)
	}
	return spec, nil
}

func languageSpecForPath(path string) (languageSpec, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	for _, spec := range languageSpecs {
		if _, ok := spec.extensions[ext]; ok {
			return spec, true
		}
	}
	return languageSpec{}, false
}
