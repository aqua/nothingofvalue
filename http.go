package nothingofvalue

import (
	"bufio"
	"embed"
	"encoding/base64"
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
	"github.com/muhlemmer/httpforwarded"
)

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

type Handler struct {
	activeSlowResponses atomic.Int32

	// Limit to how many slow responses can be outstanding at a time.  Beyond
	// this limit, requests eligible for slow responses will receive fast empty
	// ones instead.
	SlowResponseLimit int32

	// How long to spend issuing a slow response.
	SlowResponseDeadline time.Duration

	reporterSiteToken        string
	reporterSiteTokenHandler http.HandlerFunc
	reporter                 reporter.Reporter

	templateInsert sync.Mutex
	templates      sync.Map
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

func randIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.IntN(255), rand.IntN(255), rand.IntN(255), rand.IntN(255))
}

func randPort() int {
	return 20 + rand.IntN(50000)
}

func randString(alphabet []byte, n int) string {
	o := make([]byte, n)
	for i := 0; i < n; i++ {
		o[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(o)
}

func randAlpha(n int) string                 { return randString(alphabet, n) }
func randUpperAlpha(n int) string            { return randString(upperAlphabet, n) }
func randAlphaNumeric(n int) string          { return randString(alphanumerics, n) }
func randUpperAlphaNumeric(n int) string     { return randString(upperAlphaNumerics, n) }
func randAlphaMixedCaseNumeric(n int) string { return randString(alphaMixedCaseNumerics, n) }
func randUpperHex(n int) string              { return randString(upperHex, n) }
func randPassword(n int) string              { return randString(passwordChars, n) }

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

func (h *Handler) serveSlowDribble(w http.ResponseWriter) {
	defer h.activeSlowResponses.Add(-1)
	if h.activeSlowResponses.Add(1) > h.SlowResponseLimit {
		log.Printf("too many slow requests in flight, returning fast nothing")
		return
	}
	w.Header().Set("Content-Type", randMimeType())
	setHSTS(w)
	log.Printf("serving slow gibberish as %s", w.Header().Get("Content-Type"))

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
var nodeDotEnvPath = regexp.MustCompile(`(?i).*/\.env(\.\w+)*$`)
var yamlPath = regexp.MustCompile(`(?i).*/[\w-.]+.ya?ml(.bac?k(up)?)?$`)
var phpIniPath = regexp.MustCompile(`(?i).*/\.?php.ini(.bac?k(up?))?$`)
var phpInfoPath = regexp.MustCompile(`(?i).*/\.?php.?info.php$`)
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
	log.Printf("path=%s proto=%s accept-encoding=%s remote-addr=%s", r.URL.Path, r.Proto, r.Header.Get("Accept-Encoding"), r.RemoteAddr)
	switch {
	// The two real URLs here
	case r.URL.Path == "/robots.txt":
		h.serveRobotsTxt(w, r)
	case r.URL.Path == "/sitemap.xml":
		h.serveSitemap(w, r)
	case indexOrSimilar.MatchString(r.URL.Path):
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

	// Beyond this point, though, all is malign.

	// Windows Live Writer does not live here.  Exponential XML expansions do.
	case strings.HasSuffix(r.URL.Path, "/wlwmanifest.xml"):
		h.serveFile(w, "text/xml", "content/wlwmanifest.xml")
	// The only YAML files we have are also exponentially referential.
	case yamlPath.MatchString(r.URL.Path):
		h.serveFile(w, "text/yaml", "content/muchyaml.yaml")

	// Secondhand git credentials, surely valuable to someone
	case strings.HasSuffix(r.URL.Path, "/.git/config"):
		h.serveGitConfig(w)
		h.report(r, ".git/config credential scraping", []string{"BadWebBot"})
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
	case awsCredentialPath.MatchString(r.URL.Path):
		h.serveAWSCLICredentials(w)
		h.report(r, "AWS credential scraping", []string{"BadWebBot"})
	case nodeDotEnvPath.MatchString(r.URL.Path):
		h.serveNodeDotEnv(w)
		h.report(r, "Node.js .env file credential scraping", []string{"BadWebBot"})
	case phpIniPath.MatchString(r.URL.Path):
		h.servePHPIni(w)
		h.report(r, "PHP.ini file credential scraping", []string{"BadWebBot"})
	case phpInfoPath.MatchString(r.URL.Path):
		h.servePHPInfo(w)
		h.report(r, "phpinfo() credential scraping", []string{"BadWebBot"})

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
	case (strings.HasSuffix(r.URL.Path, "/_catalog") ||
		springActuatorPath.MatchString(r.URL.Path) ||
		strings.Contains(r.URL.Path, "/wp-json/")):
		h.serveContentEncoded(w, r, "application/json", "content/600d20000.json")
		h.report(r, "AJAX API vulnerability prober", []string{"BadWebBot", "WebAppAttack"})

	case xmlRPCPath.MatchString(r.URL.Path):
		// XMLRPC supports arbitrary response param structure nesting, but most
		// parsers do impose a maximum depth, so this one balances a 1000-deep
		// struct nesting with a large iteration count of the nested struct,
		// using a limited degree of million-laughs entity expansion for struct
		// keys.  The exact degree of repetition varies with the compression
		// supported by the client; gzip at 1000x1000 is 217kB, zstd manages
		// 1000x10000 in 70kB, while brotli can go 1000x100000 in only 5.4kB.
		h.serveContentEncodedFallback(w, r, "text/xml", "content/xmlrpc.xml", "content/xmlrpc.xml")
		h.report(r, "XMLRPC vulnerability prober", []string{"BadWebBot", "WebAppAttack"})

	case strings.Contains(r.URL.Path, "/wp-login") ||
		strings.Contains(r.URL.Path, "/wp-includes"):
		h.serveGenericUnhelpfulness(w, r)
		h.report(r, "Wordpress probing", []string{"BadWebBot", "WebAppAttack"})
	case strings.HasSuffix(r.URL.Path, ".php"):
		h.serveGenericUnhelpfulness(w, r)
		h.report(r, "PHP probing", []string{"BadWebBot", "WebAppAttack"})

	default:
		h.serveGenericUnhelpfulness(w, r)
	}
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

func extractRemoteAddr(r *http.Request) (net.IP, error) {
	if fh, err := httpforwarded.ParseFromRequest(r); err == nil && fh != nil {
		if f, ok := fh["for"]; ok && len(f) > 0 {
			log.Printf("f=%s", f[0])
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
	}
}
