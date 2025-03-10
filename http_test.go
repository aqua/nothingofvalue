package nothingofvalue

import (
	"bufio"
	"io"
	"net/http/httptest"
	"regexp"
	"testing"
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
