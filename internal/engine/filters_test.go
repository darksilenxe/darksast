package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scanContent runs the engine over a single inline JS source and returns
// the findings produced by the supplied rules.
func scanContent(t *testing.T, src string, rules []Rule, configure func(*Engine)) []Finding {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.js")
	require.NoError(t, os.WriteFile(path, []byte(src), 0644))

	e := New(rules)
	if configure != nil {
		configure(e)
	}

	ch := make(chan Finding, 64)
	go func() {
		_ = e.ScanDirectory(dir, ch)
	}()

	var out []Finding
	for f := range ch {
		out = append(out, f)
	}
	return out
}

// --- Layer 1: path-based filtering ---------------------------------

func TestPathFiltersExcludeTestFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src.js"), []byte("eval(userInput);\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src.test.js"), []byte("eval(userInput);\n"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "__tests__"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "__tests__", "a.js"), []byte("eval(userInput);\n"), 0644))

	e := New([]Rule{evalRule})
	ch := make(chan Finding, 16)
	go func() { _ = e.ScanDirectory(dir, ch) }()
	var found []string
	for f := range ch {
		found = append(found, filepath.Base(f.File))
	}
	assert.ElementsMatch(t, []string{"src.js"}, found, "test/spec files and __tests__ dirs should be skipped by default")
}

func TestPathFiltersExcludeVendoredDirs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src.js"), []byte("eval(x);\n"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node_modules", "lib"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node_modules", "lib", "v.js"), []byte("eval(x);\n"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "dist"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dist", "bundle.min.js"), []byte("eval(x);\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "types.d.ts"), []byte("eval(x);\n"), 0644))

	e := New([]Rule{evalRule})
	ch := make(chan Finding, 16)
	go func() { _ = e.ScanDirectory(dir, ch) }()
	var found []string
	for f := range ch {
		found = append(found, filepath.Base(f.File))
	}
	assert.ElementsMatch(t, []string{"src.js"}, found, "vendored / build / .d.ts / .min.js paths should be skipped by default")
}

func TestPathFiltersIncludeWhenOptedIn(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.test.js"), []byte("eval(x);\n"), 0644))

	e := New([]Rule{evalRule})
	e.IncludeTests = true

	ch := make(chan Finding, 4)
	go func() { _ = e.ScanDirectory(dir, ch) }()
	var found []Finding
	for f := range ch {
		found = append(found, f)
	}
	assert.Len(t, found, 1, "test files should be scanned when IncludeTests is true")
}

// --- Layer 2: suppression comments ---------------------------------

func TestSuppressionCommentDisablesLine(t *testing.T) {
	src := "eval(userInput); // scanner-disable-line\n"
	findings := scanContent(t, src, []Rule{evalRule}, nil)
	assert.Len(t, findings, 0, "scanner-disable-line should suppress the matched finding")
}

func TestSuppressionCommentDisablesNextLine(t *testing.T) {
	src := "// scanner-disable-next-line\neval(userInput);\n"
	findings := scanContent(t, src, []Rule{evalRule}, nil)
	assert.Len(t, findings, 0, "scanner-disable-next-line should suppress the next line")
}

func TestSuppressionCommentRuleScoped(t *testing.T) {
	// Rule-scoped disable: only DOM-XSS-INNERHTML-ASSIGN is suppressed,
	// JS-EVAL-EXEC should still fire.
	src := "// scanner-disable-next-line DOM-XSS-INNERHTML-ASSIGN\ndocument.body.innerHTML = userInput;\neval(userInput);\n"
	findings := scanContent(t, src, []Rule{evalRule, innerHTMLRule}, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "JS-EVAL-EXEC", findings[0].RuleID)
}

func TestSuppressionCommentIgnoredWithoutCommentSyntax(t *testing.T) {
	// String literal containing the directive must NOT be honored.
	src := "const note = 'scanner-disable-line';\neval(userInput);\n"
	findings := scanContent(t, src, []Rule{evalRule}, nil)
	assert.Len(t, findings, 1, "directives outside comments are inert")
}

// --- Layer 3: literal / regex / arg-count filters ------------------

func TestIgnoreIfLiteralSuppressesStringArgument(t *testing.T) {
	rule := testRule("EVAL-LIT", "HIGH",
		`(call_expression
            function: (identifier) @fn
            (#eq? @fn "eval")
            arguments: (arguments (_) @arg)
        ) @finding`)
	rule.IgnoreIfLiteral = []string{"arg"}
	rule.literalCaptures = map[string]struct{}{"arg": {}}

	findings := scanContent(t, "eval(\"safe\");\neval(userInput);\n", []Rule{rule}, nil)
	require.Len(t, findings, 1, "literal eval should be suppressed, identifier eval should fire")
	assert.EqualValues(t, 2, findings[0].Line)
}

func TestIgnoreIfMatchesSuppressesSafeURL(t *testing.T) {
	rule := testRule("LOC-ASSIGN", "MEDIUM",
		`(assignment_expression
            left: (member_expression property: (property_identifier) @p (#eq? @p "href"))
            right: (_) @value
        ) @finding`)
	rule.IgnoreIfMatches = map[string]string{"value": `^"#`}
	require.NoError(t, rule.compile())
	// compile() rebuilt regexp matchers from IgnoreIfMatches.

	src := `a.href = "#tab1";` + "\n" + `b.href = userInput;` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	require.Len(t, findings, 1, "anchor-only href should be suppressed by ignore_if_matches")
	assert.EqualValues(t, 2, findings[0].Line)
}

func TestRequireIfMatchesGatesOnPattern(t *testing.T) {
	rule := testRule("HASH-ALG", "MEDIUM",
		`(call_expression
            function: (member_expression
                object: (identifier) @obj (#eq? @obj "crypto")
                property: (property_identifier) @m (#eq? @m "createHash"))
            arguments: (arguments (string) @alg)
        ) @finding`)
	rule.RequireIfMatches = map[string]string{"alg": `(?i)(md5|sha1)`}
	require.NoError(t, rule.compile())

	src := `crypto.createHash("md5"); crypto.createHash("sha256");` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	require.Len(t, findings, 1, "only weak algorithm should fire")
}

func TestArgCountFilters(t *testing.T) {
	rule := testRule("CALL", "LOW",
		`(call_expression
            function: (identifier) @fn (#eq? @fn "doThing")
            arguments: (arguments) @args
        ) @finding`)
	min := 2
	rule.MinArgCount = &min
	require.NoError(t, rule.compile())

	src := "doThing(1); doThing(1,2); doThing(1,2,3);\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	assert.Len(t, findings, 2, "calls with fewer than 2 args should be filtered out")
}

// --- Layer 4: taint / constant resolution --------------------------

func TestTaintRequireTaintedDropsConstants(t *testing.T) {
	rule := testRule("REDIR", "MEDIUM",
		`(assignment_expression
            left: (member_expression property: (property_identifier) @p (#eq? @p "href"))
            right: (_) @value
        ) @finding`)
	rule.Taint = &TaintConfig{SinkCapture: "value", RequireTainted: true}
	require.NoError(t, rule.compile())

	src := `const safe = "/dashboard"; a.href = safe; b.href = req.body.next;` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	require.Len(t, findings, 1, "constant assignment should drop, tainted assignment should fire")
	assert.Contains(t, findings[0].Snippet, "req.body.next")
}

func TestTaintSanitizerCallSuppresses(t *testing.T) {
	rule := testRule("INNER", "HIGH",
		`(assignment_expression
            left: (member_expression property: (property_identifier) @p (#eq? @p "innerHTML"))
            right: (_) @value
        ) @finding`)
	rule.Taint = &TaintConfig{SinkCapture: "value", RequireTainted: true}
	require.NoError(t, rule.compile())

	src := `el.innerHTML = DOMPurify.sanitize(req.body.html);` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	assert.Len(t, findings, 0, "sanitizer-wrapped value should not fire taint-required rule")
}

func TestTaintRequireProvenTaintedDropsUnknown(t *testing.T) {
	rule := testRule("REDIR-PROVEN", "MEDIUM",
		`(assignment_expression
            left: (member_expression property: (property_identifier) @p (#eq? @p "href"))
            right: (_) @value
        ) @finding`)
	rule.Taint = &TaintConfig{SinkCapture: "value", RequireTainted: true, RequireProvenTainted: true}
	require.NoError(t, rule.compile())

	src := `const maybe = userChosen; a.href = maybe; b.href = req.body.next;` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	require.Len(t, findings, 1, "unknown sink should be dropped in proven-tainted mode")
	assert.Contains(t, findings[0].Snippet, "req.body.next")
}

func TestTaintReassignmentInvalidatesOldState(t *testing.T) {
	rule := testRule("REDIR-REASSIGN", "MEDIUM",
		`(assignment_expression
            left: (member_expression property: (property_identifier) @p (#eq? @p "href"))
            right: (_) @value
        ) @finding`)
	rule.Taint = &TaintConfig{SinkCapture: "value", RequireTainted: true}
	require.NoError(t, rule.compile())

	src := `let next = req.body.next; next = "/safe"; a.href = next;` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	assert.Len(t, findings, 0, "reassignment to constant should clear tainted state")
}

func TestTaintSanitizerThenTransformSuppresses(t *testing.T) {
	rule := testRule("INNER-TRANSFORM", "HIGH",
		`(assignment_expression
            left: (member_expression property: (property_identifier) @p (#eq? @p "innerHTML"))
            right: (_) @value
        ) @finding`)
	rule.Taint = &TaintConfig{SinkCapture: "value", RequireTainted: true}
	require.NoError(t, rule.compile())

	src := `const clean = DOMPurify.sanitize(req.body.html).trim(); el.innerHTML = clean;` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	assert.Len(t, findings, 0, "string transforms on sanitized data should remain sanitized")
}

func TestTaintArgumentsCaptureScansAllArgsByDefault(t *testing.T) {
	rule := testRule("WINDOW-OPEN", "MEDIUM",
		`(call_expression
            function: (member_expression
                object: (identifier) @o (#eq? @o "window")
                property: (property_identifier) @m (#eq? @m "open"))
            arguments: (arguments) @args
        ) @finding`)
	rule.Taint = &TaintConfig{SinkCapture: "args", RequireTainted: true}
	require.NoError(t, rule.compile())

	src := `window.open("about:blank", req.body.next);` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	assert.Len(t, findings, 1, "tainted non-first argument should be considered")
}

func TestTaintArgumentsCaptureSupportsSinkArgIndex(t *testing.T) {
	rule := testRule("WINDOW-OPEN-INDEXED", "MEDIUM",
		`(call_expression
            function: (member_expression
                object: (identifier) @o (#eq? @o "window")
                property: (property_identifier) @m (#eq? @m "open"))
            arguments: (arguments) @args
        ) @finding`)
	first := 0
	rule.Taint = &TaintConfig{SinkCapture: "args", SinkArgIndex: &first, RequireTainted: true}
	require.NoError(t, rule.compile())

	src := `window.open("about:blank", req.body.next);` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	assert.Len(t, findings, 0, "sink_arg_index should scope taint evaluation to configured arg")
}

func TestTaintAliasChainAndDestructuringWithNestedMembers(t *testing.T) {
	rule := testRule("REDIR-ALIAS", "MEDIUM",
		`(assignment_expression
            left: (member_expression property: (property_identifier) @p (#eq? @p "href"))
            right: (_) @value
        ) @finding`)
	rule.Taint = &TaintConfig{SinkCapture: "value", RequireTainted: true, RequireProvenTainted: true}
	require.NoError(t, rule.compile())

	src := `const src = req.body.next; const alias = src; const { deep } = req.body.user; a.href = alias; b.href = deep; c.href = req.body.user.next;` + "\n"
	findings := scanContent(t, src, []Rule{rule}, nil)
	assert.Len(t, findings, 3, "aliases, destructured bindings, and nested member chains should stay provably tainted")
}

// --- Layer 5: dependency gating ------------------------------------

func TestDependencyGatingSkipsRule(t *testing.T) {
	rule := evalRule
	rule.RequiresDependency = []string{"@angular/core"}
	require.NoError(t, rule.compile())

	src := "eval(userInput);\n"

	// Without gating, the rule still fires.
	findings := scanContent(t, src, []Rule{rule}, func(e *Engine) {
		e.SetProjectDependencies([]string{"react"})
	})
	assert.Len(t, findings, 1, "gating off by default — rule fires")

	// With gating, missing dependency suppresses the rule.
	findings = scanContent(t, src, []Rule{rule}, func(e *Engine) {
		e.EnableDependencyGating = true
		e.SetProjectDependencies([]string{"react"})
	})
	assert.Len(t, findings, 0, "rule should be skipped when its required dependency is absent")

	// With gating + matching dependency, rule fires.
	findings = scanContent(t, src, []Rule{rule}, func(e *Engine) {
		e.EnableDependencyGating = true
		e.SetProjectDependencies([]string{"@angular/core"})
	})
	assert.Len(t, findings, 1, "rule should fire when its required dependency is present")
}

// --- Layer 6: confidence is reported -------------------------------

func TestConfidenceDefaultsToMedium(t *testing.T) {
	findings := scanContent(t, "eval(userInput);\n", []Rule{evalRule}, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "MEDIUM", findings[0].Confidence, "confidence defaults to MEDIUM when rule does not declare one")
}

func TestConfidenceFromRule(t *testing.T) {
	rule := evalRule
	rule.Confidence = "high"
	findings := scanContent(t, "eval(userInput);\n", []Rule{rule}, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "HIGH", findings[0].Confidence, "confidence is normalized to upper case")
}
