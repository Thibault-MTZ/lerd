package plugins

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/geodro/lerd/internal/config"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var screenshotExts = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true}

func (p *Plugin) validateDocs() error {
	if p.Icon != "" {
		if strings.ToLower(path.Ext(p.Icon)) != ".svg" {
			return fmt.Errorf("icon %q must be an svg", p.Icon)
		}
		if _, err := p.resolve(p.Icon); err != nil {
			return err
		}
	}
	if p.Docs != "" {
		if strings.ToLower(path.Ext(p.Docs)) != ".md" {
			return fmt.Errorf("docs %q must be a markdown file", p.Docs)
		}
		if _, err := p.resolve(p.Docs); err != nil {
			return err
		}
	}
	for _, rel := range p.Screenshots {
		if !screenshotExts[strings.ToLower(path.Ext(rel))] {
			return fmt.Errorf("screenshot %q must be a png, jpg, gif or webp image", rel)
		}
		if _, err := p.resolve(rel); err != nil {
			return err
		}
	}
	return nil
}

// Serves reports whether the dashboard may hand out the plugin file at rel:
// anything under ui/, its icon and the screenshots the manifest lists. The rest
// of the plugin, its scripts above all, stays private.
func (p *Plugin) Serves(rel string) bool {
	if rel != path.Clean(rel) {
		return false
	}
	return strings.HasPrefix(rel, UIDir+"/") || rel == p.Icon || slices.Contains(p.Screenshots, rel)
}

// Feature is one thing a plugin adds, as the dashboard lists it.
type Feature struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
}

// Features lists what the plugin adds, named the way the user meets each one.
func (p *Plugin) Features() []Feature {
	var out []Feature
	add := func(kind, name, detail string) { out = append(out, Feature{kind, name, detail}) }
	for _, c := range p.Commands {
		add("command", "lerd "+p.Name+":"+c.Name, c.Usage)
	}
	for _, c := range p.SiteCommands {
		add("site_command", c.Label, c.Description)
	}
	if p.MCP != nil {
		for _, t := range p.MCP.Tools {
			add("mcp", p.Name+"_"+t.Name, t.Description)
		}
	}
	events := make([]string, 0, len(p.Hooks))
	for e := range p.Hooks {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, e := range events {
		add("hook", e, "")
	}
	if p.UI != nil {
		for _, pg := range []struct {
			kind string
			page *UIPage
		}{{"page", p.UI.Page}, {"site_tab", p.UI.SiteTab}, {"overview_card", p.UI.OverviewCard}, {"share_action", p.UI.ShareAction}} {
			if pg.page != nil {
				add(pg.kind, pg.page.Title, "")
			}
		}
		if p.UI.PageScript != "" {
			add("page_script", "", "")
		}
	}
	jobs := make([]string, 0, len(p.Provides))
	for j := range p.Provides {
		jobs = append(jobs, j)
	}
	sort.Strings(jobs)
	for _, j := range jobs {
		add("provides", j, "")
	}
	for _, kind := range []string{config.PluginServices, config.PluginFrameworks} {
		paths, _ := filepath.Glob(filepath.Join(p.Dir, kind, "*.yaml"))
		for _, f := range paths {
			add(strings.TrimSuffix(kind, "s"), strings.TrimSuffix(filepath.Base(f), ".yaml"), "")
		}
	}
	if p.Notifications {
		add("notifications", "", "")
	}
	return out
}

// DocsHTML renders the docs file offline, "" when there is none. Raw HTML is
// dropped, local images resolve through fileURL, and only web links stay links:
// a relative one points into a repository the reader may not have.
func (p *Plugin) DocsHTML(fileURL func(rel string) string) (string, error) {
	if p.Docs == "" {
		return "", nil
	}
	data, err := os.ReadFile(filepath.Join(p.Dir, p.Docs))
	if err != nil {
		return "", err
	}
	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(parser.WithASTTransformers(util.Prioritized(&docsLinks{p: p, fileURL: fileURL}, 100))),
	)
	var buf bytes.Buffer
	if err := md.Convert(data, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

type docsLinks struct {
	p       *Plugin
	fileURL func(string) string
}

func (t *docsLinks) Transform(doc *ast.Document, reader text.Reader, _ parser.Context) {
	source := reader.Source()
	var drop []ast.Node
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch v := n.(type) {
		case *ast.Image:
			dest := string(v.Destination)
			if isWebLink(dest) {
				return ast.WalkContinue, nil
			}
			// Relative to the docs file, the way the markdown reads where it sits.
			rel := path.Clean(path.Join(path.Dir(t.p.Docs), strings.TrimPrefix(dest, "/")))
			if !t.p.Serves(rel) {
				drop = append(drop, v)
				return ast.WalkSkipChildren, nil
			}
			v.Destination = []byte(t.fileURL(rel))
		case *ast.Link:
			if isWebLink(string(v.Destination)) {
				v.SetAttributeString("target", []byte("_blank"))
				v.SetAttributeString("rel", []byte("noopener noreferrer"))
				return ast.WalkContinue, nil
			}
			drop = append(drop, v)
		case *ast.AutoLink:
			if v.AutoLinkType == ast.AutoLinkURL && isWebLink(string(v.URL(source))) {
				v.SetAttributeString("target", []byte("_blank"))
				v.SetAttributeString("rel", []byte("noopener noreferrer"))
				return ast.WalkContinue, nil
			}
			drop = append(drop, v)
		}
		return ast.WalkContinue, nil
	})
	// A dropped link keeps its text; a dropped image goes, alt text and all.
	for _, n := range drop {
		parent := n.Parent()
		if auto, ok := n.(*ast.AutoLink); ok {
			parent.InsertBefore(parent, n, ast.NewString(auto.Label(source)))
		}
		if _, link := n.(*ast.Link); link {
			for c := n.FirstChild(); c != nil; {
				next := c.NextSibling()
				parent.InsertBefore(parent, n, c)
				c = next
			}
		}
		parent.RemoveChild(parent, n)
	}
}

func isWebLink(dest string) bool {
	return strings.HasPrefix(dest, "https://") || strings.HasPrefix(dest, "http://")
}

// CardIcon is the icon the dashboard draws for the plugin: its own, or its rail
// page's, "" when it has neither.
func (p *Plugin) CardIcon() string {
	if p.Icon != "" {
		return p.Icon
	}
	if p.UI != nil && p.UI.Page != nil {
		return p.UI.Page.Icon
	}
	return ""
}
