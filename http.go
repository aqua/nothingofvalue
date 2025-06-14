package nothingofvalue

import (
	"bufio"
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	rand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/aqua/nothingofvalue/reporter"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/muhlemmer/httpforwarded"
)

var trustForwardedHeaders = flag.Bool("trust-forwarded-headers", false, "Trust Forwarded: HTTP headers, if present")
var reportSuppressionToken = flag.String("report-suppression-token", "", "If set, no request with this token in the 'query' section (after the ? in the URL) of a request will be reported as hostile (for manual testing).")
var reportSuppressionPath = flag.String("report-suppression-path", "", "If set, no hits to paths under this prefix will be reported (for testing/demos)")

var cheapRand = rand.NewChaCha8([32]byte([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")))

func setHSTS(w http.ResponseWriter) {
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
}

//go:embed content/index.html content/index.html.gz
//go:embed content/index.html.br content/index.html.zstd
//go:embed content/muchyaml.yaml content/wlwmanifest.xml
//go:embed content/xmlrpc.xml content/xmlrpc.xml.gz content/xmlrpc.xml.br
//go:embed content/xmlrpc.xml.zstd
//go:embed content/1g.br content/10g.br content/100g.br
//go:embed content/1g.zstd content/10g.zstd
//go:embed content/tlds.txt
//go:embed content/16384.webp content/225000x225000.png.gz
//go:embed content/50000x50000.jpeg.gz
//go:embed content/overlapping.zip content/zero.gz.gz
//go:embed content/600d20000.json.gz content/600d20000.json.zstd
//go:embed content/600d20000.json.br
//go:embed content/phpinfo.html
var content embed.FS

//go:embed content/english-letters-weighted-uppercase
var frequencyWeightedUpperAlphabet []byte

//go:embed content/english-letters-weighted-lowercase
var frequencyWeightedLowerAlphabet []byte

type Handler struct {
	activeSlowResponses atomic.Int32

	// Limit to how many slow responses can be outstanding at a time.  Beyond
	// this limit, requests eligible for slow responses will receive fast empty
	// ones instead.
	SlowResponseLimit int32

	// How long to spend issuing a slow response.
	SlowResponseDeadline time.Duration

	escalations *expirable.LRU[string, int]

	reporterSiteToken        string
	reporterSiteTokenHandler http.HandlerFunc
	reporter                 reporter.Reporter

	templateInsert     sync.Mutex
	templates          sync.Map
	activeClients      map[string]bool
	activeClientsMutex sync.Mutex
}

// serve a (correct, harmless) sitemap
func (h *Handler) serveSitemap(w http.ResponseWriter, r *http.Request) {
	setHSTS(w)
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://%s/index.html</loc>
    <lastmod>2025-01-01</lastmod>
  </url>
</urlset>`, r.Host)
}

func (h *Handler) serveRobotsTxt(w http.ResponseWriter, r *http.Request) {
	setHSTS(w)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `User-Agent: *
Disallow: /
Allow: /index.html

Sitemap: https://%s/sitemap.xml
`, r.Host)
}

func (h *Handler) serveEncodedFile(w http.ResponseWriter, enc, ct, fn string) {
	log.Printf("serving %s encoded with %q", fn, enc)
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
	if enc != "" {
		w.Header().Set("Content-Encoding", enc)
	}
	setHSTS(w)
	io.Copy(w, f)
}

func (h *Handler) serveFile(w http.ResponseWriter, ct, fn string) {
	h.serveEncodedFile(w, "", ct, fn)
}

var alphabet = []byte("abcdefghijklmnopqrstuvwyz")
var upperAlphabet = []byte("ABCDEFGHIJKLMNOPQRSTUVWYZ")
var alphanumerics = []byte("abcdefghijklmnopqrstuvwyz0123456789")
var upperAlphaNumerics = []byte("ABCDEFGHIJKLMNOPQRSTUVWYZ0123456789")
var alphaMixedCaseNumerics = []byte("abcdefghijklmnopqrstuvwyzABCDEFGHIJKLMNOPQRSTUVWYZ0123456789")
var passwordChars = []byte("abcdefghijklmnopqrstuvwyzABCDEFGHIJKLMNOPQRSTUVWYZ0123456789;:,./?!@#$%^*()~`[]{}|")
var lowerHex = []byte("0123456789abcdef")
var upperHex = []byte("0123456789ABCDEF")

func randTLD() string {
	s := ""
	f, err := content.Open("content/tlds.txt")
	if err != nil {
		return ".com"
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ".biz"
	}
	for s == "" {
		if _, err := f.(io.Seeker).Seek(rand.Int64N(st.Size()), 0); err != nil {
			return ".coop"
		}
		sc := bufio.NewScanner(f)
		sc.Scan()
		sc.Scan()
		if err := sc.Err(); err != nil && err != io.EOF {
			return ".download"
		}
		s = sc.Text()
	}
	return s
}

func randUNIXPath() string {
	parts := make([]string, 2+rand.IntN(3))
	for i := range parts {
		parts[i] = randAlpha(4 + rand.IntN(8))
	}
	return "/" + strings.Join(parts, "/")
}

func randHostname() string {
	return randAlpha(4+rand.IntN(30)) + randTLD()
}

func randURL() string {
	return "https://" + randHostname() + randUNIXPath()
}

func randIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.IntN(255), rand.IntN(255), rand.IntN(255), rand.IntN(255))
}

func randPort() int {
	return 20 + rand.IntN(50000)
}

func randEmail() string {
	return randAlphaNumeric(2+rand.IntN(12)) + "@" + randHostname()
}

func randTZOffset() string {
	offset := -12 + rand.IntN(23)
	if offset < 0 {
		return fmt.Sprintf("%03d00", offset)
	} else {
		return fmt.Sprintf("%02d00", offset)
	}
}

func randHumanName() string {
	names := []string{}
	for i := 2 + rand.IntN(3); i > 0; i-- {
		names = append(names, randUpperAlpha(1)+randAlpha(2+rand.IntN(15)))
	}
	return strings.Join(names, " ")
}

func randString(alphabet []byte, n int) string {
	o := make([]byte, n)
	for i := 0; i < n; i++ {
		o[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(o)
}

// Returns word-like strings of roughly length n (in characters).
func randWordlikes(n int) []string {
	words := []string{}
	for i := 0; i < n; {
		w := randEnglishLower(1 + rand.IntN(10))
		i += len(w) + 1
		words = append(words, w)
	}
	return words
}

func randTextish(n int) string {
	words := randWordlikes(n)
	return strings.Join(words, " ")
}

func randCapitalizedTextish(n int) string {
	words := randWordlikes(n)
	if n > 0 {
		words[0] = randEnglishUpper(1) + words[0]
	}
	return strings.Join(words, " ")
}

// Returns a sentence-like things of word-like things, approximately n
// characters long.
func randSentence(n int) string {
	words := randWordlikes(n)
	if n > 0 {
		words[0] = randEnglishUpper(1) + words[0]
		words[len(words)-1] += "."
	}
	return strings.Join(words, " ")
}

func randAlpha(n int) string                 { return randString(alphabet, n) }
func randUpperAlpha(n int) string            { return randString(upperAlphabet, n) }
func randAlphaNumeric(n int) string          { return randString(alphanumerics, n) }
func randUpperAlphaNumeric(n int) string     { return randString(upperAlphaNumerics, n) }
func randAlphaMixedCaseNumeric(n int) string { return randString(alphaMixedCaseNumerics, n) }
func randEnglishCapitalized(n int) string {
	return randString(frequencyWeightedUpperAlphabet, 1) + randString(frequencyWeightedLowerAlphabet, n-1)
}
func randEnglishLower(n int) string { return randString(frequencyWeightedLowerAlphabet, n) }
func randEnglishUpper(n int) string { return randString(frequencyWeightedUpperAlphabet, n) }
func randLowerHex(n int) string     { return randString(lowerHex, n) }
func randUpperHex(n int) string     { return randString(upperHex, n) }
func randPassword(n int) string     { return randString(passwordChars, n) }

var mimeLoading sync.Once
var osMimeTypes []string
var sampleMimeTypes = []string{
	"application/octet-stream",
	"application/vnd.ctc-posml",
	"chemical/x-pdb",
	"image/jpeg",
	"text/h323",
	"video/x-matroska",
}

func loadMimeFile(filename string) ([]string, error) {
	types := make([]string, 0, 2000)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) <= 1 || fields[0][0] == '#' {
			continue
		}
		types = append(types, fields[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return types, nil
}

func randMimeType() string {
	if len(osMimeTypes) != 0 {
		return osMimeTypes[rand.IntN(len(osMimeTypes))]
	}
	return sampleMimeTypes[rand.IntN(len(sampleMimeTypes))]
}

func randBase64(n int) string {
	b := make([]byte, n)
	cheapRand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Cheap-to-serve but moderately weird HEAD response.
//
// Under HTTP2, header compression potentially gives us options for a mild
// decompression-bomb approach, but we're not because (a) the HPACK header
// dictionary has only a modest number of server response header entries, (b)
// there's a 1-byte/header best-case cost which isn't much of an expansion
// ratio, (c) a more sophisticated client isn't going to actually expand to
// the textual form of a well-known header, and (d) very few hostile crawlers
// support HTTP2 anyway.
//
// Also, in a cloud context, the response header is likely to be parsed by a
// transparent proxy, and Go's HTTP server uses a local hash for headers, so
// we're only trying to behave strangely and not actually be hostile.  The
// headers used all have HPACK dictionary entries to make them cheaper to
// ship where possible.
func (h *Handler) serveUnhelpfulHead(w http.ResponseWriter, r *http.Request) {
	setHSTS(w)
	w.Header().Set("Content-Type", randMimeType())
	w.Header().Set("Content-Length", strconv.Itoa(rand.IntN(0xfffffffff)))
	w.Header().Set("Retry-After", strconv.Itoa(1+rand.IntN(0xffff)))
	modtime := time.Unix(rand.Int64N(0xffffffff), 0)
	w.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	w.Header().Set("Vary", "*")
	w.Header().Set("Expires", time.Now().Add(1024*time.Hour).Format(http.TimeFormat))
	for i := 0; i < 10; i++ {
		w.Header().Add("Link",
			fmt.Sprintf("<https://%s/link/%s>; rel=\"%s\"",
				r.Host, randAlpha(4+rand.IntN(8)), randAlpha(2+rand.IntN(10))))
	}

}

func (h *Handler) serveGitConfig(w http.ResponseWriter) {
	setHSTS(w)
	fmt.Fprintf(w, "[user]\n\tname = %s\n\tpassword = %s\n",
		randAlpha(4+rand.IntN(12)),
		randAlpha(6+rand.IntN(40)))
	for i := 0; i < 10; i++ {
		fmt.Fprintf(w,
			"\n[credential ssh://%s@%s/%s]\n\tusername = %s\n"+
				"\thelper = \"echo password=%s\"\n",
			randAlphaNumeric(12),
			randHostname(),
			randAlphaNumeric(20),
			randAlpha(12),
			randAlphaNumeric(12))
	}
}

func (h *Handler) serveGitLogsHEAD(w http.ResponseWriter) {
	setHSTS(w)
	ts := time.Now().Add(time.Duration(-rand.IntN(1000000000)) * time.Second)
	cl := "0000000000000000000000000000000000000000"
	for i := rand.IntN(100); i > 0; i-- {
		ncl := randLowerHex(40)
		fmt.Fprintf(w, "%s %s %s <%s> %d %s commit: %s\n", cl, ncl, randHumanName(), randEmail(), ts.Unix(), randTZOffset(), randTextish(40+rand.IntN(20)))
		cl = ncl
		ts = ts.Add(time.Duration(rand.IntN(1000000)) * time.Second)
	}
}

func (h *Handler) serveAtomFTPConfig(w http.ResponseWriter) {
	fmt.Fprintf(w, `{
	"protocol": "sftp",
	"host": "%s",
	"port": %d,
	"user": "%s",
	"pass": "%s"
}`, randHostname(), 20+rand.IntN(50000),
		randAlpha(4+rand.IntN(12)), randPassword(6+rand.IntN(30)))
}

func (h *Handler) serveSendgridConfig(w http.ResponseWriter) {
	fmt.Fprintf(w, "SENDGRID_API_KEY=SG.%s.%s",
		randAlphaMixedCaseNumeric(22), randAlphaMixedCaseNumeric(43))
}

func (h *Handler) serveSublimeCodeSFTPConfig(w http.ResponseWriter) {
	fmt.Fprintf(w, `{
	"type": "sftp",
	"host": "%s",
	"port": "%d",
	"user": "%s",
	"password": "%s",
}`, randHostname(), 20+rand.IntN(50000),
		randAlpha(4+rand.IntN(12)), randPassword(6+rand.IntN(30)))
}

func (h *Handler) serveVSCodeFTPSync(w http.ResponseWriter) {
	fmt.Fprintf(w, `{
	"remotePath: "%s",
	"host": "%s",
	"username": "%s",
	"password": "%s",
	"port": "%d",
	"secure": true,
	"protocol": "sftp",
	"privateKeyPath": "%s",
	"passphrase": "%s",
	"ignore": ["\\.vscode","\\.git"]
}`,
		randUNIXPath(), randHostname(), randAlpha(4+rand.IntN(10)),
		randPassword(6+rand.IntN(30)),
		20+rand.IntN(50000), randUNIXPath(),
		randPassword(20+rand.IntN(40)))
}

func (h *Handler) serveAWSCLICredentials(w http.ResponseWriter) {
	name, sep := "default", ""
	for i := 5 + rand.IntN(5); i > 0; i-- {
		fmt.Fprintf(w, sep+`
[%s]
aws_access_key_id=A%s
aws_secret_access_key=%s
aws_session_token=%s`, name, randUpperAlphaNumeric(19),
			randBase64(20),
			randAlphaMixedCaseNumeric(60))
		name = randAlpha(4 + rand.IntN(10))
		sep = "\n"
	}
}

func (h *Handler) serveNodeDotEnv(w http.ResponseWriter) {
	fmt.Fprintf(w, `PORT=%d
API_KEY=%s
DATABASE_URL=mysql://%s:%d/%s
MYSQL_HOST=%s
MYSQL_USER=root
MYSQL_PASSWORD=%s
MYSQL_DATABASE=%s
S3BUCKET="%s"
SECRET_KEY="%s"
AWS_ACCESS_KEY_ID=A%s
AWS_SECRET_ACCESS_KEY=%s
AWS_SESSION_TOKEN=%s
`,
		randPort(),
		randAlphaMixedCaseNumeric(20),
		randHostname(), randPort(), randAlpha(4+rand.IntN(20)),
		randHostname(),
		randAlphaMixedCaseNumeric(6+rand.IntN(20)),
		randAlpha(4+rand.IntN(10)),
		randAlphaMixedCaseNumeric(40),
		randAlphaMixedCaseNumeric(30),
		randUpperAlphaNumeric(19),
		randBase64(20),
		randAlphaMixedCaseNumeric(60))
}

func (h *Handler) serveNodeFTPConfig(w http.ResponseWriter) {
	fmt.Fprintf(w, `{
	 "host": "%s",
	 "port": %d,
	 "remote": "%s",
	 "user": "%s",
	 "pass": "%s"
}`, randHostname(), randPort(), randUNIXPath(),
		randAlpha(4+rand.IntN(10)),
		randAlphaMixedCaseNumeric(40))
}

func (h *Handler) servePHPIni(w http.ResponseWriter) {
	fmt.Fprintf(w, `[php]
register_globals=on

[mail]
SMTP=%s
smtp_port=%d
username=%s
password="%s"
sendmail_from=%s

[mysql]
default_host=%s
default_port=%d
default_user=%s
default_password="%s"
`, randHostname(), randPort(),
		randAlpha(4+rand.IntN(10)),
		randPassword(6+rand.IntN(10)),
		randHostname(),
		randHostname(),
		randPort(),
		randAlpha(4+rand.IntN(10)),
		randPassword(6+rand.IntN(10)))
}

type phpInfoData struct {
}

func (i phpInfoData) Hex(n int) string          { return randUpperHex(n) }
func (i phpInfoData) Int(n int) int             { return rand.IntN(n) }
func (i phpInfoData) IntR(min, max int) int     { return min + rand.IntN(max-min) }
func (i phpInfoData) Alpha(min, max int) string { return randAlpha(min + (max - min)) }
func (i phpInfoData) Password(n int) string     { return randPassword(n) }
func (i phpInfoData) Hostname() string          { return randHostname() }
func (i phpInfoData) IP() string                { return randIP() }
func (i phpInfoData) UNIXPath() string          { return randUNIXPath() }
func (i phpInfoData) TimeHMS() string {
	return fmt.Sprintf("%02d:%02d:%02d", rand.IntN(24), rand.IntN(60), rand.IntN(60))
}

func (i phpInfoData) Date(sep string) string {
	return fmt.Sprintf("%04d%s%02d%s%02d", 2000+rand.IntN(39), sep, 1+rand.IntN(12), sep, 1+rand.IntN(31))
}

func (i phpInfoData) AutoconfCommand() string {
	cmd := []string{
		"./configure",
		"--enable-freetype",
		"--enable-libxml",
		"--enable-reflection",
		"--enable-exif",
		"--enable-sendmail",
		"--enable-mysql",
		"--enable-pgsql",
		"--enable-xmlreader",
		"--enable-xmlwriter",
		"--enable-gd",
		"--enable-php-streams",
		"--enable-wddx",
		"--with-kerberos",
		"--with-mime-magic=" + randUNIXPath(),
		"--enable-magic-quotes",
		"--enable-sqlite",
		"--enable-sqlite3",
		"--enable-xml",
		"--enable-calendar",
		"--enable-sybase",
		"--enable-unixODBC",
		"--enable-gdbm",
	}
	for i := 30 + rand.IntN(60); i > 0; i-- {
		thing := randAlpha(2 + rand.IntN(20))
		if rand.IntN(2) == 0 {
			thing = thing + "-" + randAlpha(2+rand.IntN(20))
		}
		with := ""
		n := rand.IntN(100)
		switch {
		case n < 10:
			with = "--without=" + thing
		case n < 20:
			with = "--enable-" + thing
		case n < 50:
			with = "--with-" + thing + "=" + randUNIXPath()
		default:
			with = "--with-" + thing
		}
		cmd = append(cmd, with)
	}
	for i, v := range cmd {
		cmd[i] = "'" + v + "'"
	}
	rand.Shuffle(len(cmd)-1, func(i, j int) {
		cmd[i+1], cmd[j+1] = cmd[j+1], cmd[i+1]
	})

	return strings.Join(cmd, " ")
}

func (h *Handler) servePHPInfo(w http.ResponseWriter) {
	var tmpl *template.Template
	var err error
	t, ok := h.templates.Load("phpinfo.html")
	if ok {
		tmpl = t.(*template.Template)
	} else {
		h.templateInsert.Lock()
		defer h.templateInsert.Unlock()
		tmpl, err = template.New("phpinfo.html").ParseFS(content, "content/phpinfo.html")
		if err != nil {
			log.Printf("Error parsing template phpinfo.html: %v", err)
			// return blank HTTP response
			return
		}
		h.templates.Store("phpinfo.html", tmpl)
	}
	if err = tmpl.Execute(w, &phpInfoData{}); err != nil {
		log.Printf("Error executing template phpinfo.html: %v", err)
	}
}

var wpConfigPath = regexp.MustCompile(`wp-config(.sample)?.php`)
var wpJSONFragments = regexp.MustCompile(
	`wp-json|wp-users|wp(/\w+)?/users`)

// Wordpress attacks are such a large share of bot traffic it needs some
// more detailed handling
func (h *Handler) serveWordpressAbuse(w http.ResponseWriter, r *http.Request) {
	wantsType := "generic"
	if wpJSONFragments.MatchString(r.URL.Path) || wpJSONFragments.MatchString(r.URL.RawQuery) {
		wantsType = "json"
	}

	// JSON parsers are only worth harassing if they accept a compressed
	// response
	if wantsType == "json" && r.Header.Get("Accept-Encoding") == "" {
		wantsType = "generic"
	}
	if wantsType == "json" {
		h.serveContentEncoded(w, r, "application/json", "content/600d20000.json")
	} else {
		h.serveGenericUnhelpfulness(w, r)
	}
}

func (h *Handler) serveWordpressConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/php")
	fmt.Fprintf(w, `<?php
/**
 * The base configuration for WordPress
 * %s
 *
 * @link https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
 *
 * @package WordPress
 **/
define('DB_NAME', '%s');
define('DB_USER', '%s');
define('DB_PASSWORD', '%s');
define('DB_HOST', '%s');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
define('AUTH_KEY', '%s');
define('SECURE_AUTH_KEY', '%s');
define('LOGGED_IN_KEY', '%s');
define('NONCE_KEY', '%s');
define('AUTH_SALT', '%s');
define('SECURE_AUTH_SALT', '%s');
define('LOGGED_IN_SALT', '%s');
define('NONCE_SALT', '%s');
$table_prefix = '%s_';
define('WP_DEBUG', true);
if (!defined('ABSPATH')) {
	define('ABSPATH', __DIR__ . '%s');
}
/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
 `, randSentence(100+rand.IntN(100)),
		randAlpha(8+rand.IntN(10)),
		randAlpha(8+rand.IntN(10)),
		randPassword(8+rand.IntN(10)),
		randHostname(),
		randPassword(64),
		randPassword(64),
		randPassword(64),
		randPassword(64),
		randPassword(64),
		randPassword(64),
		randPassword(64),
		randPassword(64),
		randAlpha(2+rand.IntN(6)),
		randUNIXPath())
}

func (h *Handler) serveNpmrc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, `
# %s
//registry.npmjs.org/:_authToken=%s
registry=https://registry.npmjs.org/
always-auth=true
`,
		randSentence(60+rand.IntN(40)),
		randUpperHex(64))
}

// serveLLMsTXT emulates the markdown proposed for LLMs to use to understand
// a website, because we all know "inference time" is totally the point where
// this bullshit will be used.
func (h *Handler) serveLLMsTXT(w http.ResponseWriter) {
	fmt.Fprint(w, "# LLMs.txt\n\n")
	for i := 1 + rand.IntN(10); i > 0; i-- {
		fmt.Fprintf(w, "## %s\n\n", randEnglishCapitalized(1+rand.IntN(5)))
		fmt.Fprintln(w, randSentence(40+rand.IntN(200)))
		fmt.Fprint(w, "\n")
		for j := 3 + rand.IntN(40); j > 0; j-- {
			fmt.Fprintf(w, "- [%s](%s)", randCapitalizedTextish(8+rand.IntN(15)), randURL())
			if rand.IntN(2) == 1 {
				fmt.Fprint(w, ": "+randTextish(30+rand.IntN(40)))
			}
			fmt.Fprint(w, "\n")
		}
		fmt.Fprint(w, "\n\n")
	}
}

func (h *Handler) serveSlowDribble(w http.ResponseWriter) {
	defer h.activeSlowResponses.Add(-1)
	if h.activeSlowResponses.Add(1) > h.SlowResponseLimit {
		log.Printf("too many slow requests in flight, returning fast nothing")
		return
	}
	w.Header().Set("Content-Type", randMimeType())
	setHSTS(w)
	log.Printf("serving slow gibberish as %s (deadline %s)", w.Header().Get("Content-Type"), h.SlowResponseDeadline)

	rc := http.NewResponseController(w)
	deadline := time.Now().Add(h.SlowResponseDeadline)
	rc.SetWriteDeadline(deadline)
	for i, delay := 0, 0*time.Second; i < 100; i++ {
		n := 1 + rand.IntN(16)
		buf := make([]byte, n)
		cheapRand.Read(buf)
		w.Write(buf)
		if err := rc.Flush(); err != nil {
			break
		}
		delay += time.Duration(1+rand.IntN(1000)) * time.Millisecond
		if time.Now().Add(delay).After(deadline) {
			break
		}
		time.Sleep(delay)
	}
}

var http400Codes = []int{
	http.StatusBadRequest,
	http.StatusUnauthorized,
	http.StatusPaymentRequired,
	http.StatusForbidden,
	http.StatusNotFound,
	http.StatusMethodNotAllowed,
	http.StatusNotAcceptable,
	http.StatusProxyAuthRequired,
	http.StatusRequestTimeout,
	http.StatusConflict,
	http.StatusGone,
	http.StatusLengthRequired,
	http.StatusPreconditionFailed,
	http.StatusRequestEntityTooLarge,
	http.StatusRequestURITooLong,
	http.StatusUnsupportedMediaType,
	http.StatusRequestedRangeNotSatisfiable,
	http.StatusExpectationFailed,
	http.StatusTeapot,
	http.StatusMisdirectedRequest,
	http.StatusUnprocessableEntity,
	http.StatusLocked,
	http.StatusFailedDependency,
	http.StatusTooEarly,
	http.StatusUpgradeRequired,
	http.StatusPreconditionRequired,
	http.StatusTooManyRequests,
	http.StatusRequestHeaderFieldsTooLarge,
	http.StatusUnavailableForLegalReasons,
}

func (h *Handler) serveZeroPage(w http.ResponseWriter) {
	setHSTS(w)
	w.Header().Set("Content-Type", randMimeType())
	log.Printf("serving a zero-page as %s", w.Header().Get("Content-Type"))
	z := make([]byte, 4096)
	w.Write(z)
}

func (h *Handler) serveRandom400(w http.ResponseWriter) {
	log.Printf("serving random HTTP 400 code")
	setHSTS(w)
	http.Error(w, "", http400Codes[rand.IntN(len(http400Codes))])
}

var indexOrSimilar = regexp.MustCompile(`(?i)^/+(index(\.\w+)?)?$`)
var awsCredentialPath = regexp.MustCompile(`(?i)/\.AWS_*/credentials$`)
var nodeDotEnvPath = regexp.MustCompile(`(?i)(^|.*/)\.env(\.\w+)*$`)
var nodeDotEnvQuery = regexp.MustCompile(`(?i).*url=\.env$`)
var npmrcPath = regexp.MustCompile(`(?i).*/\.npmrc(.\w+)*$`)
var yamlPath = regexp.MustCompile(`(?i).*/[\w-.]+.ya?ml(.bac?k(up)?)?$`)
var ueditorPaths = regexp.MustCompile(`ueditor.config.js`)
var unspecificWordpressPath = regexp.MustCompile(
	`(?i)^(.*(/wp-login|/wp-includes|/wp-content|/wp-json|/wp-admin)|/wp$|/wordpress$)`)
var smuggledWordpressQuery = regexp.MustCompile(
	`.*\w+=/(wp|wordpress.?\d*)/`)
var wordPressQueryParam = regexp.MustCompile(`author=\d+`)
var phpIniPath = regexp.MustCompile(`(?i).*/\.?php.ini(.bac?k(up?))?$`)
var phpInfoQuery = regexp.MustCompile(`(?i).*phpinfo\s*\(\)`)
var phpInfoPath = regexp.MustCompile(`(?i).*/\.?php.?info(.php)?$|param.*phpinfo\(\)`)
var xmlRPCPath = regexp.MustCompile(`(?i).*/xml.?rpc(\.php(.\w+)?)?$`)
var springActuatorPath = regexp.MustCompile(`(?i).*/actuator/\w+$`)

func supportsEncoding(r *http.Request, algo string) bool {
	for _, a := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if strings.TrimSpace(a) == algo {
			return true
		}
	}
	return false
}

func (h *Handler) serveContentEncoded(w http.ResponseWriter, r *http.Request, mimeType, path string) {
	h.serveContentEncodedFallback(w, r, mimeType, path, "")
}

func (h *Handler) serveContentEncodedFallback(w http.ResponseWriter, r *http.Request, mimeType, path, fallback string) {
	switch {
	case supportsEncoding(r, "br"):
		h.serveEncodedFile(w, "br", mimeType, path+".br")
	case supportsEncoding(r, "zstd"):
		h.serveEncodedFile(w, "zstd", mimeType, path+".zstd")
	case supportsEncoding(r, "gzip") || supportsEncoding(r, "gz"):
		h.serveEncodedFile(w, "gzip", mimeType, path+".gz")
	default:
		if fallback != "" {
			h.serveFile(w, mimeType, fallback)
		} else {
			// serve an empty response
		}
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	addr, _ := extractRemoteAddr(r)
	log.Printf("path=%s proto=%s accept-encoding=%s remote-addr=%s", r.URL.Path, r.Proto, r.Header.Get("Accept-Encoding"), addr)
	switch {
	// The two real URLs here
	case r.URL.Path == "/robots.txt":
		h.serveRobotsTxt(w, r)
	case r.URL.Path == "/sitemap.xml":
		h.serveSitemap(w, r)
	case indexOrSimilar.MatchString(r.URL.Path) && !undeservingOfIndex(r):
		h.serveContentEncodedFallback(w, r, "text/html", "content/index.html", "content/index.html")

	case h.reporterSiteToken != "" && r.URL.Path == h.reporterSiteToken:
		h.reporterSiteTokenHandler(w, r)

	// Requests here generally mean no harm and dig no deeper.
	case strings.HasPrefix(r.URL.Path, "/.well-known"):
		http.Error(w, "", http.StatusNotFound)
	case strings.HasPrefix(r.URL.Path, "/ads.txt"):
		http.Error(w, "", http.StatusNotFound)
	case strings.HasPrefix(r.URL.Path, "/favicon"):
		http.Error(w, "", http.StatusNotFound)

	// Bulk HEAD requests tend
	case r.Method == "HEAD":
		h.serveUnhelpfulHead(w, r)
		if unspecificWordpressPath.MatchString(r.URL.Path) {
			h.report(r, "Wordpress probing", []string{"BadWebBot", "WebAppAttack"})
		} else if strings.HasSuffix(r.URL.Path, ".php") {
			h.report(r, "PHP probing", []string{"BadWebBot", "WebAppAttack"})
		}

	// Beyond this point, though, all is malign.

	case strings.HasPrefix(r.URL.Path, "/llms.txt"):
		h.serveLLMsTXT(w)

	// Windows Live Writer does not live here.  Exponential XML expansions do.
	case strings.HasSuffix(r.URL.Path, "/wlwmanifest.xml"):
		h.serveFile(w, "text/xml", "content/wlwmanifest.xml")
	// The only YAML files we have are also exponentially referential.
	case yamlPath.MatchString(r.URL.Path) || yamlPath.MatchString(r.URL.RawQuery):
		h.serveFile(w, "text/yaml", "content/muchyaml.yaml")
	case strings.Contains(r.URL.Path, "/pom.properties"):
		h.serveContentEncodedFallback(w, r, "text/xml", "content/xmlrpc.xml", "content/xmlrpc.xml")

	// Secondhand git credentials, surely valuable to someone
	case strings.HasSuffix(r.URL.Path, "/.git/config"):
		h.serveGitConfig(w)
		h.report(r, ".git/config credential scraping", []string{"BadWebBot"})
	case strings.HasSuffix(strings.ToLower(r.URL.Path), "/.git/logs/head"):
		h.serveGitLogsHEAD(w)
		h.report(r, "git history scraping", []string{"BadWebBot"})
	case strings.HasSuffix(r.URL.Path, "ftp-sync.json") || strings.HasSuffix(r.URL.Path, "/sftp.json"):
		h.serveVSCodeFTPSync(w)
		h.report(r, "VSCode credential scraping", []string{"BadWebBot"})
	case strings.HasSuffix(r.URL.Path, "sftp-config.json"):
		h.serveSublimeCodeSFTPConfig(w)
	case strings.HasSuffix(r.URL.Path, "ftp-config.json"):
		h.serveNodeFTPConfig(w)
		h.report(r, "Node.js FTP config file credential scraping", []string{"BadWebBot"})
	case strings.HasSuffix(r.URL.Path, ".ftpconfig"):
		h.serveAtomFTPConfig(w)
		h.report(r, "Atom FTP config credential scraping", []string{"BadWebBot"})
	case strings.HasSuffix(r.URL.Path, "sendgrid.env"):
		h.serveSendgridConfig(w)
		h.report(r, "Sendgrid.env credential scraping", []string{"BadWebBot"})
	case awsCredentialPath.MatchString(r.URL.Path) ||
		awsCredentialPath.MatchString(r.URL.RawQuery):
		h.serveAWSCLICredentials(w)
		h.report(r, "AWS credential scraping", []string{"BadWebBot"})
	case nodeDotEnvPath.MatchString(r.URL.Path) || strings.Contains(r.URL.Path, "vite/env") || nodeDotEnvQuery.MatchString(r.URL.RawQuery):
		h.serveNodeDotEnv(w)
		h.report(r, "Node.js .env file credential scraping", []string{"BadWebBot", "Hacking"})
	case npmrcPath.MatchString(r.URL.Path):
		h.serveNpmrc(w, r)
		h.report(r, "Node.js .npmrc file credential scraping", []string{"BadWebBot", "Hacking"})
	case phpIniPath.MatchString(r.URL.Path):
		h.servePHPIni(w)
		h.report(r, "PHP.ini file credential scraping", []string{"BadWebBot", "Hacking"})
	case phpInfoPath.MatchString(r.URL.Path) || phpInfoQuery.MatchString(r.URL.RawQuery):
		h.servePHPInfo(w)
		h.report(r, "phpinfo() credential scraping", []string{"BadWebBot", "Hacking"})
	case strings.Contains(r.URL.RawQuery, "action=catchimage"):
		h.report(r, "hansunCMS CVE-2023-2245 vulnerability prober", []string{"BadWebBot", "WebAppAttack", "Hacking"})
		h.serveGenericUnhelpfulness(w, r)
	case ueditorPaths.MatchString(r.URL.Path):
		h.report(r, "Probing for hansunCMS", []string{"BadWebBot", "WebAppAttack", "Hacking"})
		h.serveGenericUnhelpfulness(w, r)
	case strings.Contains(r.URL.Path, "/pms") && strings.Contains(r.URL.RawQuery, "module=logging"):
		h.report(r, "ColdFusion CVE-2024-20767 vulnerability prober", []string{"BadWebBot", "WebAppAttack", "Hacking"})
		h.serveGenericUnhelpfulness(w, r)

	// While PNG, much like gzip, has a maximum compression ratio of about
	// 1024:1, it re-compresses very well.  Thanks to David Fifield
	// <david/at/bamsoftware/dot/com> for that one.
	case strings.HasSuffix(r.URL.Path, ".png") && supportsEncoding(r, "gzip"):
		h.serveEncodedFile(w, "gzip", "image/png", "content/225000x225000.png.gz")
	case (strings.HasSuffix(r.URL.Path, ".jpeg") || strings.HasSuffix(r.URL.Path, ".jpg")) && supportsEncoding(r, "gzip"):
		h.serveEncodedFile(w, "gzip", "image/jpeg", "content/50000x50000.jpeg.gz")
	// WebP needs no such contrivances
	case strings.HasSuffix(r.URL.Path, ".webp"):
		h.serveFile(w, "image/webp", "content/16384.webp")

	// The trouble with archives that contain their own metadata is that
	// the metadata can stay referential longer than you can remain solvent.
	// Thanks again to David Fifield
	// (https://www.bamsoftware.com/hacks/zipbomb/).
	case strings.HasSuffix(r.URL.Path, ".zip"):
		h.serveFile(w, "application/zip", "content/overlapping.zip")

	// JSON actually has a pretty limited attack surface, supporting none of
	// the usual cost-amplification tricks of markups like XML or YAML.
	// If the client supports content encoding we can pack a fair degree of
	// nesting and repetition to make the parse costly, but without compression
	// we fall back to an empty response.
	case strings.HasSuffix(r.URL.Path, ".json"):
		h.serveContentEncoded(w, r, "application/json", "content/600d20000.json")
	case strings.HasSuffix(r.URL.Path, "/_catalog") ||
		springActuatorPath.MatchString(r.URL.Path):
		h.serveContentEncoded(w, r, "application/json", "content/600d20000.json")
		h.report(r, "AJAX API vulnerability prober", []string{"BadWebBot", "WebAppAttack"})
	case strings.Contains(r.URL.Path, "/_all_dbs"):
		h.serveContentEncoded(w, r, "application/json", "content/600d20000.json")
		h.report(r, "CouchDB prober", []string{"BadWebBot", "WebAppAttack"})
	case strings.Contains(r.URL.Path, "microsoft.exchange.ediscovery.exporttool.application"):
		h.serveContentEncodedFallback(w, r, "text/xml", "content/xmlrpc.xml", "content/xmlrpc.xml")
		h.report(r, "MS Exchange vulnerability prober", []string{"BadWebBot", "WebAppAttack"})

	case xmlRPCPath.MatchString(r.URL.Path):
		// XMLRPC supports arbitrary response param structure nesting, but most
		// parsers do impose a maximum depth, so this one balances a 1000-deep
		// struct nesting with a large iteration count of the nested struct,
		// using a limited degree of million-laughs entity expansion for struct
		// keys.  The exact degree of repetition varies with the compression
		// supported by the client; gzip at 1000x1000 is 217kB, zstd manages
		// 1000x10000 in 70kB, while brotli can go 1000x100000 in only 5.4kB.
		h.limitClientConcurrency(w, r, func(w http.ResponseWriter, r *http.Request) {
			h.xmlrpcHandleEscalation(w, r)
		})
		h.report(r, "XMLRPC vulnerability prober", []string{"BadWebBot", "WebAppAttack"})

	case wpConfigPath.MatchString(r.URL.Path):
		h.serveWordpressConfig(w, r)
		h.report(r, "Wordpress credential scraper", []string{"BadWebBot", "WebAppAttack"})

	case isWordpressAbuse(r):
		h.serveWordpressAbuse(w, r)
		h.report(r, "Wordpress probing", []string{"BadWebBot", "WebAppAttack"})
	case strings.HasSuffix(r.URL.Path, ".php"):
		h.serveGenericUnhelpfulness(w, r)
		h.report(r, "PHP probing", []string{"BadWebBot", "WebAppAttack"})
	default:
		h.serveGenericUnhelpfulness(w, r)
	}
}

func isWordpressAbuse(r *http.Request) bool {
	return phpInfoQuery.MatchString(r.URL.RawQuery) || smuggledWordpressQuery.MatchString(r.URL.RawQuery) || wordPressQueryParam.MatchString(r.URL.RawQuery)
}

var urlParamRE = regexp.MustCompile(`url=`)

func isURLParamAbuse(r *http.Request) bool {
	return urlParamRE.MatchString(r.URL.RawQuery)
}

func undeservingOfIndex(r *http.Request) bool {
	log.Printf("considering %q", r.URL.RawQuery)
	return isWordpressAbuse(r) || isURLParamAbuse(r)
}

func (h *Handler) serveGenericUnhelpfulness(w http.ResponseWriter, r *http.Request) {
	d100 := rand.IntN(100)
	switch {
	// generic XML response; for now reuse the XMLRPC one.
	case strings.HasSuffix(r.URL.Path, ".xml"):
		h.serveContentEncodedFallback(w, r, "text/xml", "content/xmlrpc.xml", "content/xmlrpc.xml")

	// gzip can only do 1024:1, but if the client will also transport encode,
	// we can offer 1024^2:1.
	case strings.HasSuffix(r.URL.Path, ".gz") && supportsEncoding(r, "gzip"):
		h.serveEncodedFile(w, "gzip", "application/gzip", "content/zero.gz.gz")

	// brotli requires no such tricks:
	case supportsEncoding(r, "br"):
		h.serveEncodedFile(w, "br", "text/plain", "content/100g.br")

	// zstd is a complex format, and can probably be manipulated better than
	// this, but 1G in 32k isn't bad.  Good compressor.  Pity about the
	// whole destroying-democracy thing, though.
	case supportsEncoding(r, "zstd"):
		h.serveEncodedFile(w, "zstd", "text/plain", "content/1g.zstd")

	// Beyond this point we have no specific way to be unhelpful and just pick
	// randomly from a selection of unhelpful things.
	case d100 < 50:
		h.serveSlowDribble(w)
	case d100 < 70:
		h.serveRandom400(w)
	case d100 < 90:
		h.serveZeroPage(w)
	default:
		log.Printf("serving nothing")
		// serve nothing
	}
}

func escalationKey(r *http.Request) string {
	if ip, err := extractRemoteAddr(r); err == nil {
		return ip.String() + " " + r.URL.Path
	}
	return r.URL.Path
}

func (h *Handler) limitClientConcurrency(w http.ResponseWriter, r *http.Request, fn func(w http.ResponseWriter, r *http.Request)) {
	k := ""
	if ip, err := extractRemoteAddr(r); err == nil {
		k = ip.String()
	} else {
		k = r.RemoteAddr
	}
	h.activeClientsMutex.Lock()
	if h.activeClients[k] {
		h.activeClientsMutex.Unlock()
		http.Error(w, "", 429)
		return
	} else {
		h.activeClients[k] = true
		h.activeClientsMutex.Unlock()
	}
	fn(w, r)
	h.activeClientsMutex.Lock()
	delete(h.activeClients, k)
	h.activeClientsMutex.Unlock()
}

// XML-RPC abuse bots tend to be quite aggressive, sending high-qps
// attack streams.  Give them a couple of quick million-laughs responses
// first, but after that start tarpitting, and if they keep calling,
// start returning 404s to stop spending a thread on them.
//
// Wrapped by limitClientConcurrency so any further requests sent while
// a tarpitted request is active are given 429s instead.
func (h *Handler) xmlrpcHandleEscalation(w http.ResponseWriter, r *http.Request) {
	k := escalationKey(r)
	attempt, _ := h.escalations.Get(k)
	if attempt < 2 {
		h.serveContentEncodedFallback(w, r, "text/xml", "content/xmlrpc.xml", "content/xmlrpc.xml")
	} else if attempt < 50 {
		tw := &TarpitWriter{
			w:           w,
			chunk:       20,
			chunkJitter: 10,
			delay:       200 * time.Millisecond,
			httpRC:      http.NewResponseController(w),
			jitter:      1 * time.Second,
		}
		tw.httpRC.SetWriteDeadline(time.Now().Add(h.SlowResponseDeadline))
		makeLaughsXMLRPC(min(attempt, 8), tw)
	} else {
		http.Error(w, "", 404)
	}
	h.escalations.Add(k, attempt+1)
}

func makeLaughsXMLRPC(iter int, w io.Writer) {
	s := `<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE rpcz [
 <!ENTITY rpc "rpc">
`
	s += fmt.Sprintf("<!ENTITY rpc0 \"&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;\">\n")
	last := 0
	for j := 1; j <= iter; j++ {
		s += fmt.Sprintf("<!ENTITY rpc%d \"", j)
		for k := 0; k < 10; k++ {
			s += fmt.Sprintf("&rpc%d;", j-1)
		}
		s += "\">\n"
		last = j
	}
	s += fmt.Sprintf(`<methodResponse>
  <params>
    <param>
        <value><string>&rpc%d;</string></value>
    </param>
  </params>
</methodResponse>`, last)
	w.Write([]byte(s))
}

func extractRemoteAddr(r *http.Request) (net.IP, error) {
	if *trustForwardedHeaders {
		if fh, err := httpforwarded.ParseFromRequest(r); err == nil && fh != nil {
			if f, ok := fh["for"]; ok && len(f) > 0 {
				if strings.HasPrefix(f[0], "[") && strings.HasSuffix(f[0], "]") {
					f[0] = f[0][1 : len(f[0])-1]
				}
				if ip := net.ParseIP(f[0]); ip != nil {
					return ip, nil
				} else if ip, _, err := net.SplitHostPort(f[0]); err == nil {
					return net.ParseIP(ip), nil
				}
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip, nil
		}
		return nil, err
	} else {
		log.Printf("unparseable IP %q: %v", r.RemoteAddr, err)
		return nil, fmt.Errorf("unparseable IP: %s: %v", r.RemoteAddr, err)
	}
}

func (h *Handler) report(r *http.Request, comment string, categories []string) error {
	if h.reporter == nil {
		return nil
	}
	if *reportSuppressionToken != "" && strings.Contains(r.URL.RawQuery, *reportSuppressionToken) {
		log.Printf("URL query string contains magic suppression token, not reporting")
		return nil
	}
	if *reportSuppressionPath != "" && strings.HasPrefix(r.URL.Path, *reportSuppressionPath) {
		log.Printf("URL path under suppressed path, not reporting")
		return nil
	}
	ip, err := extractRemoteAddr(r)
	if err != nil {
		return err
	}
	comment += fmt.Sprintf("; %s %s", r.Method, r.URL.Path)
	return h.reporter.Report(&reporter.Report{
		IP:         ip,
		Timestamp:  time.Now(),
		Comment:    comment,
		Categories: categories,
	})
}

func (h *Handler) AddReporter(r reporter.Reporter) {
	h.reporter = r
	h.reporterSiteToken, h.reporterSiteTokenHandler = r.SiteVerificationHandler()
}

func NewHandler() *Handler {
	mimeLoading.Do(func() {
		osMimeTypes, _ = loadMimeFile("/etc/mime.types")
	})

	return &Handler{
		SlowResponseLimit:    10,
		SlowResponseDeadline: 29 * time.Second,
		escalations:          expirable.NewLRU[string, int](500, nil, 4*time.Hour),
		activeClients:        map[string]bool{},
	}
}
