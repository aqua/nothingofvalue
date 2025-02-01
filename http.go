package nothingofvalue

import (
	"bufio"
	"embed"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	rand "math/rand/v2"
	"net/http"
	"regexp"
	"strings"
)

var cheapRand = rand.NewChaCha8([32]byte([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")))

//go:embed content/robots.txt content/index.html
//go:embed content/muchyaml.yaml content/wlwmanifest.xml
//go:embed content/1g.br content/10g.br content/100g.br
//go:embed content/1g.zstd content/10g.zstd
//go:embed content/tlds.txt
//go:embed content/16384.webp content/225000x225000.png.gz
//go:embed content/50000x50000.jpeg.gz
//go:embed content/overlapping.zip content/zero.gz.gz
var content embed.FS

type Handler struct {
}

func (h Handler) serveEncodedFile(w http.ResponseWriter, enc, ct, fn string) {
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
	io.Copy(w, f)
}

func (h Handler) serveFile(w http.ResponseWriter, ct, fn string) {
	h.serveEncodedFile(w, "", ct, fn)
}

var alphabet = []byte("abcdefghijklmnopqrstuvwyz")
var upperAlphabet = []byte("ABCDEFGHIJKLMNOPQRSTUVWYZ")
var alphanumerics = []byte("abcdefghijklmnopqrstuvwyz0123456789")
var upperAlphaNumerics = []byte("ABCDEFGHIJKLMNOPQRSTUVWYZ0123456789")
var alphaMixedCaseNumerics = []byte("abcdefghijklmnopqrstuvwyzABCDEFGHIJKLMNOPQRSTUVWYZ0123456789")
var passwordChars = []byte("abcdefghijklmnopqrstuvwyzABCDEFGHIJKLMNOPQRSTUVWYZ0123456789;:,.<>/?!@#$$%^&*()~`[]{}|")

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
		f.(io.Seeker).Seek(rand.Int64N(st.Size()), 0)
		sc := bufio.NewScanner(f)
		sc.Scan()
		sc.Scan()
		w := sc.Text()
		if w != "" {
			return w
		}
	}
	return ".coop"
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
func randPassword(n int) string              { return randString(passwordChars, n) }

func randBase64(n int) string {
	b := make([]byte, n)
	cheapRand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func (h Handler) serveGitConfig(w http.ResponseWriter) {
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

func (h Handler) serveAtomFTPConfig(w http.ResponseWriter) {
	fmt.Fprintf(w, `{
	"protocol": "sftp",
	"host": "%s",
	"port": %d,
	"user": "%s",
	"pass": "%s"
}`, randHostname(), 20+rand.IntN(50000),
		randAlpha(4+rand.IntN(12)), randPassword(6+rand.IntN(30)))
}

func (h Handler) serveSublimeCodeSFTPConfig(w http.ResponseWriter) {
	fmt.Fprintf(w, `{
	"type": "sftp",
	"host": "%s",
	"port": "%d",
	"user": "%s",
	"password": "%s",
}`, randHostname(), 20+rand.IntN(50000),
		randAlpha(4+rand.IntN(12)), randPassword(6+rand.IntN(30)))
}

func (h Handler) serveVSCodeFTPSync(w http.ResponseWriter) {
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

func (h Handler) serveAWSCLICredentials(w http.ResponseWriter) {
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

func (h Handler) serveNodeDotEnv(w http.ResponseWriter) {
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

func (h Handler) servePHPIni(w http.ResponseWriter) {
	fmt.Fprintf(w, `[php]
register_globals=on

[mail function]
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

var indexOrSimilar = regexp.MustCompile(`(?i)/+(index(\.\w+)?)?$`)
var awsCredentialPath = regexp.MustCompile(`(?i)/\.AWS_*/credentials$`)
var nodeDotEnvPath = regexp.MustCompile(
	`(?i).*/\.env(.bac?k(up)?|.old|.save|.dev(el(opment)?)?|.prod(uction)?)?$`)
var yamlPath = regexp.MustCompile(`(?i).*/[\w-.]+.yaml(.bac?k(up)?)?$`)
var phpIniPath = regexp.MustCompile(`(?i).*/php.ini(.bac?k(up?))?$`)

func supportsEncoding(r *http.Request, algo string) bool {
	for _, a := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if strings.TrimSpace(a) == algo {
			return true
		}
	}
	return false
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("path=%s accept-encoding=%s", r.URL.Path, r.Header.Get("Accept-Encoding"))
	switch {
	// The two real URLs here
	case r.URL.Path == "/robots.txt":
		h.serveFile(w, "text/plain", "content/robots.txt")
	case indexOrSimilar.MatchString(r.URL.Path):
		h.serveFile(w, "text/html", "content/index.html")

	// Requests here generally mean no harm and dig no deeper.
	case strings.HasPrefix(r.URL.Path, "/.well-known"):
		http.Error(w, "", http.StatusNotFound)
	case strings.HasPrefix(r.URL.Path, "/ads.txt"):
		http.Error(w, "", http.StatusNotFound)
	case strings.HasPrefix(r.URL.Path, "/favicon"):
		http.Error(w, "", http.StatusNotFound)

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
	case strings.HasSuffix(r.URL.Path, "ftp-sync.json"):
		h.serveVSCodeFTPSync(w)
	case strings.HasSuffix(r.URL.Path, "sftp-config.json"):
		h.serveSublimeCodeSFTPConfig(w)
	case strings.HasSuffix(r.URL.Path, ".ftpconfig"):
		h.serveAtomFTPConfig(w)
	case strings.HasSuffix(r.URL.Path, ".ftpconfig"):
		h.serveAtomFTPConfig(w)
	case awsCredentialPath.MatchString(r.URL.Path):
		h.serveAWSCLICredentials(w)
	case nodeDotEnvPath.MatchString(r.URL.Path):
		h.serveNodeDotEnv(w)
	case phpIniPath.MatchString(r.URL.Path):
		h.servePHPIni(w)

	// While PNG, much like gzip, has a maximum compression ratio of about
	// 1024:1, it re-compresses very well.  Thanks to David Fifield
	// <david/at/bamsoftware/dot/com> for that one.
	case strings.HasSuffix(r.URL.Path, ".png") && supportsEncoding(r, "gzip"):
		h.serveEncodedFile(w, "gzip", "image/png", "content/225000x225000.png.gz")
	case (strings.HasSuffix(r.URL.Path, ".jpeg") || strings.HasSuffix(r.URL.Path, ".jpg")) && supportsEncoding(r, "gzip"):
		h.serveEncodedFile(w, "gzip", "image/png", "content/50000x50000.jpeg.gz")
	// WebP needs no such contrivances
	case strings.HasSuffix(r.URL.Path, ".webp"):
		h.serveFile(w, "image/webp", "content/16384.webp")

	// The trouble with archives that contain their own metadata is that
	// the metadata can stay referential longer than you can remain solvent.
	// Thanks again to David Fifield
	// (https://www.bamsoftware.com/hacks/zipbomb/).
	case strings.HasSuffix(r.URL.Path, ".zip"):
		h.serveFile(w, "application/zip", "content/overlapping.zip")

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

	default:
		// serve nothing
	}
}

func NewHandler() *Handler {
	return &Handler{}
}
