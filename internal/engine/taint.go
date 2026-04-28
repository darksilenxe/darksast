package engine

import (
	"log"

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

// vettedSanitizerMemberCalls enumerates known-safe fully-qualified
// sanitizer calls as root object -> method name.
var vettedSanitizerMemberCalls = map[string]map[string]struct{}{
	"DOMPurify": {
		"sanitize": {},
	},
	"validator": {
		"escape": {},
	},
	"xssFilters": {
		"inHTMLData":            {},
		"inDoubleQuotedAttr":    {},
		"inSingleQuotedAttr":    {},
		"inUnQuotedAttr":        {},
		"uriPathInHTMLData":     {},
		"uriInDoubleQuotedAttr": {},
		"uriInSingleQuotedAttr": {},
	},
	"he": {
		"encode": {},
	},
}

// commonSanitizerIdentifiers covers bare-identifier sanitizer calls.
var commonSanitizerIdentifiers = map[string]struct{}{
	"encodeURIComponent": {},
	"encodeURI":          {},
}

// sanitizerPassthroughMethods preserve sanitized status when called on
// an already-sanitized receiver.
var sanitizerPassthroughMethods = map[string]struct{}{
	"trim": {},
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
		if nameNode != nil && valueNode != nil {
			flavor := model.resolveCapture(valueNode, source, nil)
			names := collectBoundIdentifiers(nameNode, source)
			for _, name := range names {
				model.setIdentifierFlavor(name, flavor)
			}
		}
	}

	if node.Type() == "assignment_expression" {
		leftNode := node.ChildByFieldName("left")
		rightNode := node.ChildByFieldName("right")
		if leftNode != nil && rightNode != nil {
			flavor := model.resolveCapture(rightNode, source, nil)
			names := collectBoundIdentifiers(leftNode, source)
			for _, name := range names {
				model.setIdentifierFlavor(name, flavor)
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
		if obj != nil && rootsTainted(obj, source) {
			return taintTainted
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
		obj := fn.ChildByFieldName("object")
		if prop != nil && obj != nil {
			method := prop.Content(source)
			root := rootIdentifier(obj, source)
			if isVettedSanitizerMemberCall(root, method) {
				return taintSanitized
			}
			if _, ok := sanitizerPassthroughMethods[method]; ok {
				if classifyExpression(obj, source) == taintSanitized {
					return taintSanitized
				}
			}

			// e.g. req.query.id() — treat root-tainted member chains as
			// tainted even when wrapped in an unknown call.
			if rootsTainted(obj, source) {
				return taintTainted
			}
		}
	}
	return taintUnknown
}

func isVettedSanitizerMemberCall(root, method string) bool {
	if root == "" || method == "" {
		return false
	}
	methods, ok := vettedSanitizerMemberCalls[root]
	if !ok {
		return false
	}
	_, ok = methods[method]
	return ok
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
func (m *fileTaintModel) resolveCapture(node *sitter.Node, source []byte, cfg *TaintConfig) taintFlavor {
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

	if node.Type() == "parenthesized_expression" && node.NamedChildCount() > 0 {
		return m.resolveCapture(node.NamedChild(0), source, cfg)
	}

	// For arguments lists, either resolve a configured positional
	// argument or merge all arguments.
	if node.Type() == "arguments" {
		if cfg != nil && cfg.SinkArgIndex != nil {
			idx := *cfg.SinkArgIndex
			argCount := int(node.NamedChildCount())
			if idx < 0 || idx >= argCount {
				log.Printf("WARNING: rule configuration error: sink_arg_index %d out of range (argument count=%d, valid range=0..%d)", idx, argCount, argCount-1)
				return taintUnknown
			}
			return m.resolveCapture(node.NamedChild(idx), source, cfg)
		}
		if node.NamedChildCount() == 0 {
			return taintUnknown
		}
		flavor := taintConstant
		for i := 0; i < int(node.NamedChildCount()); i++ {
			flavor = mergeFlavor(flavor, m.resolveCapture(node.NamedChild(i), source, cfg))
		}
		return flavor
	}

	flavor := classifyExpression(node, source)
	if flavor != taintUnknown {
		return flavor
	}

	identifiers := collectReferencedIdentifiers(node, source)
	if len(identifiers) == 0 {
		return taintUnknown
	}

	allKnownConstants := true
	hasKnownSanitized := false
	for _, name := range identifiers {
		if m.tainted[name] {
			return taintTainted
		}
		if m.sanitized[name] {
			hasKnownSanitized = true
		}
		if !m.constants[name] {
			allKnownConstants = false
		}
	}
	if hasKnownSanitized && !allKnownConstants {
		return taintSanitized
	}
	if allKnownConstants {
		return taintConstant
	}
	return taintUnknown
}

func (m *fileTaintModel) setIdentifierFlavor(name string, flavor taintFlavor) {
	if name == "" {
		return
	}
	delete(m.constants, name)
	delete(m.sanitized, name)
	delete(m.tainted, name)

	switch flavor {
	case taintConstant:
		m.constants[name] = true
	case taintSanitized:
		m.sanitized[name] = true
	case taintTainted:
		m.tainted[name] = true
	}
}

func collectBoundIdentifiers(node *sitter.Node, source []byte) []string {
	if node == nil {
		return nil
	}
	out := make(map[string]struct{})
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "identifier", "shorthand_property_identifier_pattern":
			name := n.Content(source)
			if name != "" {
				out[name] = struct{}{}
			}
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(node)

	names := make([]string, 0, len(out))
	for name := range out {
		names = append(names, name)
	}
	return names
}

func collectReferencedIdentifiers(node *sitter.Node, source []byte) []string {
	if node == nil {
		return nil
	}
	out := make(map[string]struct{})
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "identifier":
			name := n.Content(source)
			if name != "" {
				out[name] = struct{}{}
			}
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(node)

	names := make([]string, 0, len(out))
	for name := range out {
		names = append(names, name)
	}
	return names
}

func rootIdentifier(node *sitter.Node, source []byte) string {
	for node != nil {
		switch node.Type() {
		case "identifier":
			return node.Content(source)
		case "member_expression", "subscript_expression":
			node = node.ChildByFieldName("object")
		case "call_expression":
			node = node.ChildByFieldName("function")
		default:
			return ""
		}
	}
	return ""
}
