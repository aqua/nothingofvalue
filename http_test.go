package nothingofvalue

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/aqua/nothingofvalue/reporter"
)

func re(p string) *regexp.Regexp {
	return regexp.MustCompile(p)
}

func readerMatches(in io.Reader, re *regexp.Regexp) bool {
	s := bufio.NewScanner(in)
	for s.Scan() {
		if re.Match(s.Bytes()) {
			return true
		}
	}
	return false
}

func TestFixedResponses(t *testing.T) {
	cases := []struct {
		path  string
		code  int
		match *regexp.Regexp
	}{
		{"/", 200, re("Nothing valued is here")},
		{"/robots.txt", 200, re("Disallow: /")},
		{"/sitemap.xml", 200, re("<loc>.*</loc>")},
		{"/favicon.ico", 404, nil},
		{"/wlwmanifest.xml", 200, re("<?xml")},
		{"/xmlrpc.php", 200, re("<param>")},
		{"/.git/config", 200, re(`\[credential `)},
		{"/.git/logs/HEAD", 200, re(`commit: `)},
		{"/.ftp-sync.json", 200, re(`remotePath: *".*"`)},
		{"/sftp-config.json", 200, re(`"user": *"`)},
		{"/ftp-config.json", 200, re(`"user": *"`)},
		{"/.ftpconfig", 200, re(`"user": *"`)},
		{"/.aws/credentials", 200, re(`aws_access_key_id=A`)},
		{"/.env", 200, re(`API_KEY=.+`)},
		{"/.env.production.foo", 200, re(`API_KEY=.+`)},
		{"/php.ini", 200, re(`default_user=.+`)},
		{"/phpinfo.php", 200, re(`href="https?://www.php.net/`)},
		{"/sendgrid.env", 200, re(`SENDGRID_API_KEY=SG\..+`)},
	}
	h := NewHandler()
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		resp := w.Result()
		if resp.StatusCode != c.code {
			t.Errorf("GET %s returned HTTP %d, want %d", c.path, resp.StatusCode, c.code)
			continue
		}
		if c.match != nil && !readerMatches(resp.Body, c.match) {
			t.Errorf("GET %s response body did not match %s", c.path, c.match)
		}
	}
}

func TestParseRemoteAddr(t *testing.T) {
	otfh := *trustForwardedHeaders
	*trustForwardedHeaders = true
	defer func() { *trustForwardedHeaders = otfh }()
	cases := []struct {
		remoteAddr string
		forwarded  string
		xforwarded string
		want       net.IP
		fail       bool
	}{
		{"127.0.0.1:1234", "", "", net.IPv4(127, 0, 0, 1), false},
		{"0.0.0.1:1234", "", "", net.IPv4(0, 0, 0, 1), false},
		{"[ff::]:1234", "", "", net.ParseIP("ff::"), false},
		{"[::1]:1234", "", "", net.ParseIP("::1"), false},
		{"[::1%lo0]:1234", "", "", net.ParseIP("[::1]"), true}, // not sure if this needs handling
		{"127.0.0.2:1234", "for=192.0.2.1; proto=http", "", net.IPv4(192, 0, 2, 1), false},
		{"127.0.0.2:1234", "for=\"[2001:5a8::68]\";proto=https", "", net.ParseIP("2001:5a8::68"), false},
		{"127.0.0.2:1234", "for=\"[2001:5a8::68]:1234\";proto=https", "", net.ParseIP("2001:5a8::68"), false},
	}
	for i, c := range cases {
		req := &http.Request{RemoteAddr: c.remoteAddr, Header: http.Header{}}
		if c.forwarded != "" {
			req.Header.Add("Forwarded", c.forwarded)
		}
		if got, err := extractRemoteAddr(req); err != nil && !c.fail {
			t.Errorf("case %d: parse error on %v: %v", i, req, err)
		} else if !got.Equal(c.want) {
			t.Errorf("case %d: want %s, got %s", i, c.want, got)
		}
	}
}

func TestReporting(t *testing.T) {
	cases := []struct {
		path  string
		match *regexp.Regexp
	}{
		{"/", nil},
		{"/.git/config", re(`credential scraping`)},
		{"/.git/logs/HEAD", re(`git history scraping`)},
		{"/.env", re(`credential scraping`)},
		{"/.AWS/credentials", re(`credential scraping`)},
		{"/wp-json/abuseme", re(`vulnerability prober`)},
	}
	ch := make(chan string, 1)
	h := NewHandler()
	h.AddReporter(reporter.NewLogOnlyReporter(ch))
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		_ = w.Result()
		if c.match != nil {
			report := <-ch
			if !c.match.MatchString(report) {
				t.Errorf("for %q, expected report matching %s", c.path, c.match)
			}
		}
	}
}
