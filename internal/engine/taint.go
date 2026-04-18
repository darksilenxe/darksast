package engine

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// taintFlavor classifies a captured argument's resolved provenance.
type taintFlavor int

const (
	taintUnknown   taintFlavor = iota // could not classify
	taintConstant                     // resolves to a literal/string/number
	taintTainted                      // traces to a known untrusted source
	taintSanitized                    // wrapped in a known sanitizer call
)

// commonSanitizers are member-call expressions whose result is treated
// as cleansed regardless of what their argument is. The check is shape
// based: we look for a call whose function ends in one of these names.
var commonSanitizers = map[string]struct{}{
	"sanitize":          {}, // DOMPurify.sanitize, sanitize-html
	"escape":            {}, // validator.escape, lodash.escape
	"escapeHTML":        {},
	"escapeHtml":        {},
	"encodeURIComponent": {},
	"encodeURI":         {},
	"normalize":         {}, // path.normalize
}

// commonSanitizerIdentifiers covers bare-identifier sanitizer calls.
var commonSanitizerIdentifiers = map[string]struct{}{
	"encodeURIComponent": {},
	"encodeURI":          {},
	"Number":             {},
	"parseInt":           {},
	"parseFloat":         {},
}

// commonTaintSourceObjects is the set of root identifiers whose member
// access is treated as untrusted input (e.g. `req.body`, `process.env`).
var commonTaintSourceObjects = map[string]struct{}{
	"req":      {},
	"request":  {},
	"ctx":      {},
	"context":  {},
	"location": {},
	"document": {}, // document.location, document.URL, document.referrer
	"window":   {}, // window.name, window.location
	"process":  {}, // process.argv, process.env
}

// fileTaintModel captures lightweight per-file constant tracking. We
// resolve simple `const NAME = "literal";` / `const NAME = sanitize(x);`
// declarations so rules opting into taint analysis can treat the
// referenced identifier as a constant or sanitized value.
type fileTaintModel struct {
	// constants maps identifier name -> true when the variable was
	// initialized from a literal value.
	constants map[string]bool
	// sanitized identifiers initialized from a known sanitizer call.
	sanitized map[string]bool
	// tainted identifiers initialized from a known untrusted source.
	tainted map[string]bool
}

func newFileTaintModel() *fileTaintModel {
	return &fileTaintModel{
		constants: make(map[string]bool),
		sanitized: make(map[string]bool),
		tainted:   make(map[string]bool),
	}
}

// buildFileTaintModel walks the AST and records simple declarations.
func buildFileTaintModel(root *sitter.Node, source []byte) *fileTaintModel {
	model := newFileTaintModel()
	if root == nil {
		return model
	}
	walkForTaint(root, source, model)
	return model
}

func walkForTaint(node *sitter.Node, source []byte, model *fileTaintModel) {
	if node == nil {
		return
	}

	if node.Type() == "variable_declarator" {
		nameNode := node.ChildByFieldName("name")
		valueNode := node.ChildByFieldName("value")
		if nameNode != nil && valueNode != nil && nameNode.Type() == "identifier" {
			name := nameNode.Content(source)
			switch classifyExpression(valueNode, source) {
			case taintConstant:
				model.constants[name] = true
			case taintSanitized:
				model.sanitized[name] = true
			case taintTainted:
				model.tainted[name] = true
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		walkForTaint(node.Child(i), source, model)
	}
}

// classifyExpression returns the taintFlavor of an arbitrary expression
// node. The classification is intentionally conservative: anything we
// cannot reason about is reported as taintUnknown.
func classifyExpression(node *sitter.Node, source []byte) taintFlavor {
	if node == nil {
		return taintUnknown
	}

	switch node.Type() {
	case "string", "number", "true", "false", "null", "regex":
		return taintConstant
	case "template_string":
		// A template string is constant only when it has no
		// `${...}` substitutions.
		if node.NamedChildCount() == 0 {
			return taintConstant
		}
		// Substitutions inherit the most pessimistic flavor of any
		// inner expression.
		flavor := taintConstant
		for i := 0; i < int(node.NamedChildCount()); i++ {
			child := node.NamedChild(i)
			if child == nil {
				continue
			}
			if child.Type() == "template_substitution" && child.NamedChildCount() > 0 {
				inner := classifyExpression(child.NamedChild(0), source)
				flavor = mergeFlavor(flavor, inner)
			}
		}
		return flavor
	case "unary_expression":
		// e.g. -1, !flag — treat as constant when the operand is.
		operand := node.ChildByFieldName("argument")
		return classifyExpression(operand, source)
	case "binary_expression":
		left := classifyExpression(node.ChildByFieldName("left"), source)
		right := classifyExpression(node.ChildByFieldName("right"), source)
		return mergeFlavor(left, right)
	case "call_expression":
		return classifyCall(node, source)
	case "member_expression":
		// Treat known untrusted source roots as tainted.
		obj := node.ChildByFieldName("object")
		if obj != nil && obj.Type() == "identifier" {
			if _, ok := commonTaintSourceObjects[obj.Content(source)]; ok {
				return taintTainted
			}
		}
		return taintUnknown
	case "identifier":
		// An identifier is unresolved here — callers consult the
		// per-file taint model to look up declarations.
		return taintUnknown
	}
	return taintUnknown
}

// classifyCall handles call_expression nodes by inspecting the callee.
func classifyCall(node *sitter.Node, source []byte) taintFlavor {
	fn := node.ChildByFieldName("function")
	if fn == nil {
		return taintUnknown
	}

	switch fn.Type() {
	case "identifier":
		if _, ok := commonSanitizerIdentifiers[fn.Content(source)]; ok {
			return taintSanitized
		}
	case "member_expression":
		prop := fn.ChildByFieldName("property")
		if prop != nil {
			name := prop.Content(source)
			if _, ok := commonSanitizers[name]; ok {
				return taintSanitized
			}
		}
		// e.g. req.query.id() — treat root-tainted member chains as
		// tainted even when wrapped in an unknown call.
		obj := fn.ChildByFieldName("object")
		if obj != nil && rootsTainted(obj, source) {
			return taintTainted
		}
	}
	return taintUnknown
}

// rootsTainted walks down the receiver chain of a member expression
// and returns true when its root identifier is a known taint source.
func rootsTainted(node *sitter.Node, source []byte) bool {
	for node != nil {
		switch node.Type() {
		case "identifier":
			_, ok := commonTaintSourceObjects[node.Content(source)]
			return ok
		case "member_expression", "subscript_expression":
			node = node.ChildByFieldName("object")
		case "call_expression":
			node = node.ChildByFieldName("function")
		default:
			return false
		}
	}
	return false
}

// mergeFlavor combines two taintFlavors using the precedence:
//   tainted > sanitized > unknown > constant.
// In other words, any tainted operand makes the result tainted; otherwise
// the most "interesting" non-constant flavor wins.
func mergeFlavor(a, b taintFlavor) taintFlavor {
	if a == taintTainted || b == taintTainted {
		return taintTainted
	}
	if a == taintSanitized || b == taintSanitized {
		return taintSanitized
	}
	if a == taintUnknown || b == taintUnknown {
		return taintUnknown
	}
	return taintConstant
}

// resolveCapture classifies a captured node using both its expression
// shape and the per-file constant/sanitizer/source model.
func (m *fileTaintModel) resolveCapture(node *sitter.Node, source []byte) taintFlavor {
	if node == nil {
		return taintUnknown
	}

	if node.Type() == "identifier" {
		name := node.Content(source)
		if m.tainted[name] {
			return taintTainted
		}
		if m.sanitized[name] {
			return taintSanitized
		}
		if m.constants[name] {
			return taintConstant
		}
		return taintUnknown
	}

	// For arguments lists and similar wrappers, classify the first
	// non-trivial named child.
	if node.Type() == "arguments" && node.NamedChildCount() > 0 {
		return m.resolveCapture(node.NamedChild(0), source)
	}

	flavor := classifyExpression(node, source)
	if flavor != taintUnknown {
		return flavor
	}

	// Fall back to substring identifier scanning for nested expressions
	// like `prefix + userId`.
	text := node.Content(source)
	for name := range m.tainted {
		if containsIdentifier(text, name) {
			return taintTainted
		}
	}
	for name := range m.sanitized {
		if containsIdentifier(text, name) {
			return taintSanitized
		}
	}
	return taintUnknown
}

// containsIdentifier returns true when name appears as a standalone
// identifier (not a substring of a larger identifier) in text.
func containsIdentifier(text, name string) bool {
	if name == "" {
		return false
	}
	idx := 0
	for {
		hit := strings.Index(text[idx:], name)
		if hit < 0 {
			return false
		}
		start := idx + hit
		end := start + len(name)
		before := byte(' ')
		after := byte(' ')
		if start > 0 {
			before = text[start-1]
		}
		if end < len(text) {
			after = text[end]
		}
		if !isIdentChar(before) && !isIdentChar(after) {
			return true
		}
		idx = end
	}
}

func isIdentChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_' || b == '$':
		return true
	}
	return false
}
