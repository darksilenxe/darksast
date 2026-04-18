// Package fetcher downloads JavaScript from a live URL so the scanner
// engine can analyze it as if it were on disk. It is intentionally
// minimal: a single page is fetched, inline <script> blocks and
// linked external <script src="..."> files are persisted into an
// output directory, and a small manifest.json maps each saved file
// back to its origin URL.
package fetcher

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Default safety limits. Callers can override most of these via Options.
const (
	defaultTimeout      = 30 * time.Second
	defaultMaxBytes     = 5 * 1024 * 1024 // 5 MiB per response
	defaultMaxRedirects = 5
	defaultUserAgent    = "JavaScript-Security-Scanner/1.0 (+https://github.com/darksilenxe/JavaScript-Scanner)"
)

// Options configures a Fetcher. Zero values fall back to safe defaults.
type Options struct {
	// Timeout bounds each HTTP request (page + each linked script).
	Timeout time.Duration
	// UserAgent is sent in the User-Agent request header.
	UserAgent string
	// MaxBytes caps the size of any single response body. Responses
	// larger than this are truncated and an error is recorded.
	MaxBytes int64
	// SameOriginOnly, when true, skips external <script src> URLs whose
	// host differs from the page URL. Inline scripts are always saved.
	SameOriginOnly bool
	// MaxRedirects caps redirect chains for safety.
	MaxRedirects int
}

// Manifest records the result of a fetch run so findings can be traced
// back to their origin URL.
type Manifest struct {
	PageURL string          `json:"page_url"`
	FetchAt time.Time       `json:"fetched_at"`
	Files   []ManifestEntry `json:"files"`
}

// ManifestEntry describes one saved JavaScript file.
type ManifestEntry struct {
	LocalFile  string `json:"local_file"`
	SourceURL  string `json:"source_url,omitempty"`
	Kind       string `json:"kind"` // "inline" or "external"
	HTTPStatus int    `json:"http_status,omitempty"`
	Bytes      int64  `json:"bytes"`
	Error      string `json:"error,omitempty"`
}

// Fetch downloads JavaScript from pageURL into outDir. It returns the
// manifest describing what was saved, including any per-file errors,
// and a hard error only if the page itself could not be fetched or the
// output directory could not be prepared.
func Fetch(pageURL, outDir string, opts Options) (*Manifest, error) {
	if pageURL == "" {
		return nil, errors.New("fetcher: empty page URL")
	}
	parsedPage, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("fetcher: invalid URL %q: %w", pageURL, err)
	}
	if parsedPage.Scheme != "http" && parsedPage.Scheme != "https" {
		return nil, fmt.Errorf("fetcher: unsupported URL scheme %q (only http/https)", parsedPage.Scheme)
	}

	opts = applyDefaults(opts)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("fetcher: create output dir %q: %w", outDir, err)
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return nil, fmt.Errorf("fetcher: resolve output dir %q: %w", outDir, err)
	}

	client := newClient(opts)

	pageBody, pageStatus, err := download(client, pageURL, opts)
	if err != nil {
		return nil, fmt.Errorf("fetcher: download page: %w", err)
	}
	if pageStatus < 200 || pageStatus >= 300 {
		return nil, fmt.Errorf("fetcher: page returned HTTP %d", pageStatus)
	}

	doc, err := html.Parse(strings.NewReader(string(pageBody)))
	if err != nil {
		return nil, fmt.Errorf("fetcher: parse HTML: %w", err)
	}

	manifest := &Manifest{
		PageURL: pageURL,
		FetchAt: time.Now().UTC(),
	}

	usedNames := make(map[string]int)
	inlineIdx := 0

	walkScripts(doc, func(src, inline string) {
		if inline != "" {
			inlineIdx++
			name := fmt.Sprintf("inline_%d.js", inlineIdx)
			fullPath, perr := safeJoin(absOut, name)
			if perr != nil {
				manifest.Files = append(manifest.Files, ManifestEntry{
					LocalFile: name, Kind: "inline", Error: perr.Error(),
				})
				return
			}
			if werr := os.WriteFile(fullPath, []byte(inline), 0o644); werr != nil {
				manifest.Files = append(manifest.Files, ManifestEntry{
					LocalFile: name, Kind: "inline", Error: werr.Error(),
				})
				return
			}
			manifest.Files = append(manifest.Files, ManifestEntry{
				LocalFile: name, Kind: "inline", Bytes: int64(len(inline)),
			})
			return
		}

		// External script: resolve relative to page URL.
		ref, perr := url.Parse(src)
		if perr != nil {
			manifest.Files = append(manifest.Files, ManifestEntry{
				SourceURL: src, Kind: "external", Error: perr.Error(),
			})
			return
		}
		resolved := parsedPage.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			// Skip data: javascript: blob: etc.
			return
		}
		if opts.SameOriginOnly && !sameOrigin(parsedPage, resolved) {
			return
		}

		name := uniqueName(usedNames, deriveName(resolved))
		fullPath, perr := safeJoin(absOut, name)
		if perr != nil {
			manifest.Files = append(manifest.Files, ManifestEntry{
				LocalFile: name, SourceURL: resolved.String(), Kind: "external",
				Error: perr.Error(),
			})
			return
		}

		body, status, derr := download(client, resolved.String(), opts)
		entry := ManifestEntry{
			LocalFile: name, SourceURL: resolved.String(), Kind: "external",
			HTTPStatus: status,
		}
		if derr != nil {
			entry.Error = derr.Error()
			manifest.Files = append(manifest.Files, entry)
			return
		}
		if status < 200 || status >= 300 {
			entry.Error = fmt.Sprintf("HTTP %d", status)
			manifest.Files = append(manifest.Files, entry)
			return
		}
		if werr := os.WriteFile(fullPath, body, 0o644); werr != nil {
			entry.Error = werr.Error()
			manifest.Files = append(manifest.Files, entry)
			return
		}
		entry.Bytes = int64(len(body))
		manifest.Files = append(manifest.Files, entry)
	})

	if err := writeManifest(absOut, manifest); err != nil {
		return manifest, fmt.Errorf("fetcher: write manifest: %w", err)
	}
	return manifest, nil
}

// SavedCount returns the number of files successfully written to disk.
func (m *Manifest) SavedCount() int {
	if m == nil {
		return 0
	}
	n := 0
	for _, f := range m.Files {
		if f.Error == "" {
			n++
		}
	}
	return n
}

// --- internals -----------------------------------------------------------

func applyDefaults(o Options) Options {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.UserAgent == "" {
		o.UserAgent = defaultUserAgent
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = defaultMaxBytes
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = defaultMaxRedirects
	}
	return o
}

func newClient(o Options) *http.Client {
	return &http.Client{
		Timeout: o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= o.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", o.MaxRedirects)
			}
			return nil
		},
	}
}

func download(client *http.Client, target string, o Options) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", o.UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, o.MaxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(body)) > o.MaxBytes {
		return body[:o.MaxBytes], resp.StatusCode, fmt.Errorf("response exceeded max bytes (%d)", o.MaxBytes)
	}
	return body, resp.StatusCode, nil
}

// walkScripts visits every <script> element in the document, calling
// fn either with src!="" (external) or with inline!="" (inline body).
// Scripts with both an src and a body have only the src reported (the
// browser ignores the inline body in that case).
func walkScripts(n *html.Node, fn func(src, inline string)) {
	if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
		var src, typeAttr string
		for _, a := range n.Attr {
			switch strings.ToLower(a.Key) {
			case "src":
				src = strings.TrimSpace(a.Val)
			case "type":
				typeAttr = strings.ToLower(strings.TrimSpace(a.Val))
			}
		}
		// Treat empty type or known JS module/script types as JS;
		// skip data templates like "application/json" or "text/template".
		jsType := typeAttr == "" ||
			typeAttr == "module" ||
			typeAttr == "text/javascript" ||
			typeAttr == "application/javascript" ||
			typeAttr == "application/ecmascript" ||
			typeAttr == "text/ecmascript"

		if jsType {
			if src != "" {
				fn(src, "")
			} else {
				var sb strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						sb.WriteString(c.Data)
					}
				}
				body := strings.TrimSpace(sb.String())
				if body != "" {
					fn("", body)
				}
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkScripts(c, fn)
	}
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		a.Port() == b.Port()
}

// deriveName picks a deterministic, sanitized filename from a URL path.
// Falls back to a sha1 hash when the path provides nothing usable.
func deriveName(u *url.URL) string {
	base := path.Base(u.Path)
	base = strings.TrimSpace(base)
	// Drop any traversal segments.
	base = strings.ReplaceAll(base, "..", "_")
	base = strings.ReplaceAll(base, "/", "_")
	base = strings.ReplaceAll(base, "\\", "_")
	if base == "" || base == "." || base == "/" {
		base = ""
	}
	if base == "" {
		sum := sha1.Sum([]byte(u.String()))
		base = hex.EncodeToString(sum[:8]) + ".js"
	}
	lower := strings.ToLower(base)
	if !strings.HasSuffix(lower, ".js") &&
		!strings.HasSuffix(lower, ".mjs") &&
		!strings.HasSuffix(lower, ".cjs") {
		base += ".js"
	}
	// Allow only a conservative set of characters in filenames.
	var sb strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

func uniqueName(used map[string]int, name string) string {
	if used[name] == 0 {
		used[name] = 1
		return name
	}
	used[name]++
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	return fmt.Sprintf("%s_%d%s", stem, used[name], ext)
}

// safeJoin joins root with name and ensures the resulting path stays
// inside root, defending against traversal via crafted filenames.
func safeJoin(root, name string) (string, error) {
	cleaned := filepath.Clean(name)
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute filename rejected: %q", name)
	}
	full := filepath.Join(root, cleaned)
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "..") || rel == ".." {
		return "", fmt.Errorf("path escapes output dir: %q", name)
	}
	return full, nil
}

func writeManifest(outDir string, m *Manifest) error {
	target := filepath.Join(outDir, "manifest.json")
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o644)
}
