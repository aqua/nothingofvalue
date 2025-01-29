package nothingofvalue

import (
	"embed"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

//go:embed robots.txt index.html
var content embed.FS

type Handler struct {
}

func (h Handler) serveFile(w http.ResponseWriter, ct, fn string) {
	f, err := content.Open(fn)
	if err != nil {
		log.Printf("missing embedded file %s: %v", fn, err)
		// serve nothing
		return
	}
	defer f.Close()
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	io.Copy(w, f)
}

var indexOrSimilar = regexp.MustCompile(`(?i)/+(index(\.\w+)?)?$`)

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/robots.txt":
		h.serveFile(w, "text/plain", "robots.txt")
	case indexOrSimilar.MatchString(r.URL.Path):
		h.serveFile(w, "text/html", "index.html")
	case strings.HasPrefix(r.URL.Path, "/.well-known"):
		http.Error(w, "", http.StatusNotFound)
	default:
		// serve nothing
	}
}

func NewHandler() *Handler {
	return &Handler{}
}
