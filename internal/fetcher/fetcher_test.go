package fetcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: build an httptest server that serves an HTML page plus a
// linked external script. The handler also echoes a configurable
// large body for max-bytes tests.
func newTestServer(t *testing.T, html, externalJS string, largeBytes int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(html))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(externalJS))
	})
	if largeBytes > 0 {
		mux.HandleFunc("/large.js", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(strings.Repeat("a", largeBytes)))
		})
	}
	mux.HandleFunc("/missing.js", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux)
}

func TestFetchInlineAndExternal(t *testing.T) {
	html := `<!doctype html><html><head>
<script>var x = eval(userInput);</script>
<script src="/app.js"></script>
</head><body></body></html>`

	srv := newTestServer(t, html, "console.log('hello');", 0)
	defer srv.Close()

	out := t.TempDir()
	m, err := Fetch(srv.URL+"/", out, Options{SameOriginOnly: true})
	require.NoError(t, err)
	require.NotNil(t, m)

	require.Len(t, m.Files, 2)
	assert.Equal(t, 2, m.SavedCount())

	// Inline file is named inline_1.js and contains the script body.
	inlinePath := filepath.Join(out, "inline_1.js")
	body, err := os.ReadFile(inlinePath)
	require.NoError(t, err)
	assert.Contains(t, string(body), "eval(userInput)")

	// External file derived from URL path.
	extPath := filepath.Join(out, "app.js")
	body, err = os.ReadFile(extPath)
	require.NoError(t, err)
	assert.Equal(t, "console.log('hello');", string(body))

	// Manifest is written and parseable.
	mfData, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	require.NoError(t, err)
	var got Manifest
	require.NoError(t, json.Unmarshal(mfData, &got))
	assert.Equal(t, srv.URL+"/", got.PageURL)
	assert.Len(t, got.Files, 2)
}

func TestFetchSameOriginFiltersThirdParty(t *testing.T) {
	// Use a fixed third-party URL pointing at a non-routable host so
	// that even if filtering broke we wouldn't hit the network.
	html := `<!doctype html><html><head>
<script src="https://example.invalid/cdn.js"></script>
<script src="/app.js"></script>
</head></html>`

	srv := newTestServer(t, html, "var ok = 1;", 0)
	defer srv.Close()

	out := t.TempDir()
	m, err := Fetch(srv.URL+"/", out, Options{SameOriginOnly: true})
	require.NoError(t, err)

	// Only the same-origin script should be present.
	require.Len(t, m.Files, 1)
	assert.Equal(t, "external", m.Files[0].Kind)
	assert.Contains(t, m.Files[0].SourceURL, srv.URL)
}

func TestFetchEnforcesMaxBytes(t *testing.T) {
	html := `<!doctype html><html><script src="/large.js"></script></html>`
	srv := newTestServer(t, html, "", 4096)
	defer srv.Close()

	out := t.TempDir()
	m, err := Fetch(srv.URL+"/", out, Options{MaxBytes: 1024, SameOriginOnly: true})
	require.NoError(t, err)
	require.Len(t, m.Files, 1)
	assert.NotEmpty(t, m.Files[0].Error, "expected max-bytes violation to be recorded")
	assert.Contains(t, m.Files[0].Error, "max bytes")

	// File should not have been written.
	_, statErr := os.Stat(filepath.Join(out, m.Files[0].LocalFile))
	assert.True(t, os.IsNotExist(statErr), "no file should be written when over the cap")
}

func TestFetchRejectsNonHTTPScheme(t *testing.T) {
	_, err := Fetch("ftp://example.com/", t.TempDir(), Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported URL scheme")
}

func TestFetchHandlesExternalErrorsWithoutFailing(t *testing.T) {
	html := `<!doctype html><html><script src="/missing.js"></script></html>`
	srv := newTestServer(t, html, "", 0)
	defer srv.Close()

	out := t.TempDir()
	m, err := Fetch(srv.URL+"/", out, Options{SameOriginOnly: true})
	require.NoError(t, err, "missing external scripts must not abort the run")
	require.Len(t, m.Files, 1)
	assert.Equal(t, http.StatusNotFound, m.Files[0].HTTPStatus)
	assert.NotEmpty(t, m.Files[0].Error)
}

func TestFetchPageError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Fetch(srv.URL+"/", t.TempDir(), Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestFetchSkipsNonJSScriptTypes(t *testing.T) {
	html := `<!doctype html><html><head>
<script type="application/json">{"k":"v"}</script>
<script>var realJs = 1;</script>
</head></html>`

	srv := newTestServer(t, html, "", 0)
	defer srv.Close()

	out := t.TempDir()
	m, err := Fetch(srv.URL+"/", out, Options{SameOriginOnly: true})
	require.NoError(t, err)
	require.Len(t, m.Files, 1)
	assert.Equal(t, "inline", m.Files[0].Kind)
}

func TestSafeJoinRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	_, err := safeJoin(root, "../escape.js")
	assert.Error(t, err)
	_, err = safeJoin(root, "/etc/passwd")
	assert.Error(t, err)
	good, err := safeJoin(root, "ok.js")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(good, root))
}

func TestDeriveNameFallback(t *testing.T) {
	cases := []struct {
		in   string
		want string // suffix expectation
	}{
		{"https://example.com/", ".js"},
		{"https://example.com/path/", ".js"},
		{"https://example.com/foo.js", "foo.js"},
		{"https://example.com/foo.mjs", "foo.mjs"},
		{"https://example.com/weird name!.js?x=1", "weird_name_.js"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			u, err := url.Parse(c.in)
			require.NoError(t, err)
			got := deriveName(u)
			assert.True(t, strings.HasSuffix(got, c.want), fmt.Sprintf("got %q want suffix %q", got, c.want))
		})
	}
}
