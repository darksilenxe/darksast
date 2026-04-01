module javascript-security-scanner

go 1.26.1

require (
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/stretchr/testify v1.10.0 // indirect

exclude github.com/smacker/go-tree-sitter/javascript v0.0.1
