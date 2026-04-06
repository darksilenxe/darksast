package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

// Finding represents a discovered vulnerability
type Finding struct {
	File      string `json:"file"`
	Line      uint32 `json:"line"`
	Column    uint32 `json:"column"`
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	Framework string `json:"framework"`
	Snippet   string `json:"snippet"`
}

// extractSnippet returns the trimmed text of the source line at the given
// zero-based row index, capped at 120 characters.
func extractSnippet(sourceCode []byte, row uint32) string {
	lines := bytes.Split(sourceCode, []byte("\n"))
	if int(row) >= len(lines) {
		return ""
	}
	line := strings.TrimSpace(string(lines[row]))
	const maxLen = 120
	if len(line) > maxLen {
		return line[:maxLen] + "..."
	}
	return line
}

// VariableState tracks the lifecycle of a specific variable
type VariableState struct {
	Name        string
	IsTainted   bool
	IsSanitized bool // The "firewall" flag
}

// SymbolTable holds the state of all variables in the current execution scope
type SymbolTable struct {
	Variables map[string]*VariableState
}

// Engine holds the configuration for the scanning process
type Engine struct {
	Rules []Rule
}

// New constructs an Engine
func New(rules []Rule) *Engine {
	return &Engine{
		Rules: rules,
	}
}

func findingNodeForMatch(rule Rule, match *sitter.QueryMatch) *sitter.Node {
	var widestNode *sitter.Node
	var widestSpan uint32

	for _, capture := range match.Captures {
		if capture.Node == nil {
			continue
		}

		if rule.compiled.CaptureNameForId(capture.Index) == "finding" {
			return capture.Node
		}

		span := capture.Node.EndByte() - capture.Node.StartByte()
		if widestNode == nil || span > widestSpan {
			widestNode = capture.Node
			widestSpan = span
		}
	}

	return widestNode
}

func (e *Engine) matchRules(tree *sitter.Tree, sourceCode []byte, path string, findings chan<- Finding) {
	for _, rule := range e.Rules {
		if err := rule.compile(); err != nil {
			fmt.Printf("[-] Warning: %v\n", err)
			continue
		}

		cursor := sitter.NewQueryCursor()
		cursor.Exec(rule.compiled, tree.RootNode())

		for {
			match, ok := cursor.NextMatch()
			if !ok {
				break
			}

			filteredMatch := cursor.FilterPredicates(match, sourceCode)
			if len(filteredMatch.Captures) == 0 {
				continue
			}

			root := tree.RootNode()
			row := root.StartPoint().Row
			col := root.StartPoint().Column
			if node := findingNodeForMatch(rule, filteredMatch); node != nil {
				row = node.StartPoint().Row
				col = node.StartPoint().Column
			}

			findings <- Finding{
				File:      path,
				Line:      uint32(row + 1),
				Column:    uint32(col + 1),
				RuleID:    rule.ID,
				Severity:  rule.Severity,
				Framework: normalizeFramework(rule.Framework),
				Snippet:   extractSnippet(sourceCode, uint32(row)),
			}
		}

		cursor.Close()
	}
}

func (e *Engine) ScanDirectory(targetDir string, findings chan<- Finding) error {
	var wg sync.WaitGroup

	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".js" || ext == ".jsx" || ext == ".ts" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs" {
			wg.Add(1)
			go e.scanFile(path, &wg, findings)
		}
		return nil
	})

	go func() {
		wg.Wait()
		close(findings)
	}()

	return err
}

// scanFile parses the code and kicks off the AST walker
func (e *Engine) scanFile(path string, wg *sync.WaitGroup, findings chan<- Finding) {
	defer wg.Done()

	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())

	tree, _ := parser.ParseCtx(context.Background(), nil, content)
	if tree == nil {
		return
	}

	e.matchRules(tree, content, path, findings)

	// Initialize our state tracker for this specific file
	symTable := &SymbolTable{
		Variables: make(map[string]*VariableState),
	}

	// Start walking the tree from the root node
	e.walkNode(tree.RootNode(), content, symTable, path, findings)
}

// walkNode recursively traverses the AST, functioning as a state machine
func (e *Engine) walkNode(node *sitter.Node, sourceCode []byte, symTable *SymbolTable, path string, findings chan<- Finding) {
	if node == nil {
		return
	}

	// --- 1. THE SOURCES (Data Entry) ---
	if node.Type() == "variable_declarator" {
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			varName := nameNode.Content(sourceCode)

			// For our prototype: if it's named "payload" or comes from a loop variable, taint it.
			isTainted := (varName == "payload" || varName == "key")

			symTable.Variables[varName] = &VariableState{
				Name:        varName,
				IsTainted:   isTainted,
				IsSanitized: false,
			}
		}
	}

	// --- 2. THE SANITIZERS (The Firewall Check) ---
	if node.Type() == "if_statement" {
		conditionNode := node.ChildByFieldName("condition")

		if conditionNode != nil && conditionNode.NamedChildCount() > 0 {
			exprNode := conditionNode.NamedChild(0)

			if exprNode.Type() == "binary_expression" {
				left := exprNode.ChildByFieldName("left")
				right := exprNode.ChildByFieldName("right")

				if left != nil && right != nil {
					leftContent := left.Content(sourceCode)
					rightContent := right.Content(sourceCode)

					if rightContent == "'__proto__'" || rightContent == "\"__proto__\"" {
						if state, exists := symTable.Variables[leftContent]; exists {
							state.IsSanitized = true
						}
					}
				}
			}
		}
	}

	// --- 3. THE SINKS (Vulnerability Execution) ---
	if node.Type() == "assignment_expression" {
		leftNode := node.ChildByFieldName("left")

		if leftNode != nil && leftNode.Type() == "subscript_expression" {
			indexNode := leftNode.ChildByFieldName("index")

			if indexNode != nil {
				keyName := indexNode.Content(sourceCode)

				if state, exists := symTable.Variables[keyName]; exists {
					if state.IsTainted && !state.IsSanitized {
						row := node.StartPoint().Row
						findings <- Finding{
							File:      path,
							Line:      uint32(row + 1),
							Column:    uint32(node.StartPoint().Column + 1),
							RuleID:    "proto-assignment",
							Severity:  "HIGH",
							Framework: "JavaScript",
							Snippet:   extractSnippet(sourceCode, uint32(row)),
						}
					}
				}
			}
		}
	}

	// --- 4. RECURSION ---
	for i := 0; i < int(node.ChildCount()); i++ {
		e.walkNode(node.Child(i), sourceCode, symTable, path, findings)
	}
}

func normalizeFramework(framework string) string {
	if framework == "" {
		return "JavaScript"
	}
	return framework
}
