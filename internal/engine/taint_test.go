package engine

import (
	"context"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseTree(t *testing.T, src string) (*sitter.Tree, []byte) {
	t.Helper()
	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(src))
	require.NoError(t, err)
	return tree, []byte(src)
}

func findFirstNodeByType(node *sitter.Node, nodeType string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == nodeType {
		return node
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if found := findFirstNodeByType(node.NamedChild(i), nodeType); found != nil {
			return found
		}
	}
	return nil
}

func TestCollectBoundIdentifiersFromDestructuringPatterns(t *testing.T) {
	tree, source := parseTree(t, `const {a, b: c, ...rest} = req.body;`)
	defer tree.Close()

	declarator := findFirstNodeByType(tree.RootNode(), "variable_declarator")
	require.NotNil(t, declarator)
	nameNode := declarator.ChildByFieldName("name")
	require.NotNil(t, nameNode)

	names := collectBoundIdentifiers(nameNode, source)
	assert.ElementsMatch(t, []string{"a", "c", "rest"}, names)
}

func TestCollectReferencedIdentifiersFromComplexExpression(t *testing.T) {
	tree, source := parseTree(t, `sink(foo + bar.baz(qux) + `+"`x${zap}`"+`);`)
	defer tree.Close()

	call := findFirstNodeByType(tree.RootNode(), "call_expression")
	require.NotNil(t, call)
	args := call.ChildByFieldName("arguments")
	require.NotNil(t, args)
	require.Greater(t, int(args.NamedChildCount()), 0)

	ids := collectReferencedIdentifiers(args.NamedChild(0), source)
	assert.ElementsMatch(t, []string{"foo", "bar", "qux", "zap"}, ids)
}

func TestBuildFileTaintModelTracksConstantBinaryAssignments(t *testing.T) {
	tree, source := parseTree(t, `const base = "https://api.example"; const fullUrl = base + "/v1"; sink(fullUrl);`)
	defer tree.Close()

	model := buildFileTaintModel(tree.RootNode(), source)
	assert.Equal(t, taintConstant, model.resolveIdentifier("fullUrl"))
}

func TestBuildFileTaintModelTracksSanitizedBinaryAssignments(t *testing.T) {
	tree, source := parseTree(t, `const clean = DOMPurify.sanitize(req.body.html) + ""; sink(clean);`)
	defer tree.Close()

	model := buildFileTaintModel(tree.RootNode(), source)
	assert.Equal(t, taintSanitized, model.resolveIdentifier("clean"))
}

func TestBuildFileTaintModelTracksSanitizedPassthroughAssignments(t *testing.T) {
	tree, source := parseTree(t, `const clean = DOMPurify.sanitize(req.body.html).toLowerCase(); sink(clean);`)
	defer tree.Close()

	model := buildFileTaintModel(tree.RootNode(), source)
	assert.Equal(t, taintSanitized, model.resolveIdentifier("clean"))
}

func TestBuildFileTaintModelTracksChainedSanitizedPassthroughAssignments(t *testing.T) {
	tree, source := parseTree(t, `const clean = DOMPurify.sanitize(req.body.html).trimStart().trimEnd(); sink(clean);`)
	defer tree.Close()

	model := buildFileTaintModel(tree.RootNode(), source)
	assert.Equal(t, taintSanitized, model.resolveIdentifier("clean"))
}

func TestBuildFileTaintModelTracksTaintedBinaryAssignments(t *testing.T) {
	tree, source := parseTree(t, `const nextUrl = "/go?next=" + req.body.next; sink(nextUrl);`)
	defer tree.Close()

	model := buildFileTaintModel(tree.RootNode(), source)
	assert.Equal(t, taintTainted, model.resolveIdentifier("nextUrl"))
}
