package reporter

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"
	"rievo.dev/sst/go-abuseipdb/pkg/abuseipdb"
)

var reportTestIPOnly = flag.Bool("abuseipdb-report-test-ip-only", false, "Override the real IP, report only a test address")

type IPNets []net.IPNet

func (in *IPNets) String() string { return fmt.Sprint(*in) }
func (in *IPNets) Set(v string) error {
	*in = []net.IPNet{}
	for _, iv := range strings.Split(v, ",") {
		if _, net, err := net.ParseCIDR(iv); err != nil {
			return err
		} else if net == nil {
			return fmt.Errorf("%q did not parse to a subnet", v)
		} else {
			*in = append(*in, *net)
		}
	}
	return nil
}

var neverReportIPNets IPNets

const neverReportDefaults = "127.0.0.0/8,10.0.0.0/8,169.254.0.0/16,192.168.0.0/16,172.16.0.0/12,100.64.0.0/10,::1/128,fc00::/7,fe80::/64,ff00::/8"

func init() {
	neverReportIPNets.Set(neverReportDefaults)
	flag.Var(&neverReportIPNets, "abuseipdb-never-report-cidr", "comma-separated list of CIDR subnets never to report as abusive")
}

type Report struct {
	IP         net.IP
	Timestamp  time.Time
	Categories []string
	Comment    string
}

type Reporter interface {
	Report(*Report) error
	SiteVerificationHandler() (string, http.HandlerFunc)
}

type AbuseIPDBReportCacheKey string

func makeCacheKey(report *Report) AbuseIPDBReportCacheKey {
	return AbuseIPDBReportCacheKey(report.IP.String() + "\t" + strings.Join(report.Categories, ","))
}

type AbuseIPDBReporter struct {
	client                *abuseipdb.Client
	siteVerificationToken string
	ch                    chan *Report
	startReporter         sync.Once
	limiter               *rate.Limiter
	// reportCache stores semi-recent reports by the thing we reported them
	// for; we re-report if the categories change, but not otherwise.
	reportCache *expirable.LRU[AbuseIPDBReportCacheKey, bool]
}

func (r *AbuseIPDBReporter) Report(report *Report) error {
	r.startReporter.Do(func() {
		r.ch = make(chan *Report, 20)
		go r.reporter()
	})
	for _, n := range neverReportIPNets {
		if n.Contains(report.IP) {
			log.Printf("%s is in %s, not reporting", report.IP, n.String())
			return nil
		}
	}
	ck := makeCacheKey(report)
	if _, ok := r.reportCache.Get(ck); ok {
		log.Printf("%s recently reported for %q, not re-reporting", report.IP, report.Categories)
	} else if r.limiter.Allow() {
		r.ch <- report
		r.reportCache.Add(ck, true)
	}
	return nil
}

func (r *AbuseIPDBReporter) makeOptions(report *Report) *abuseipdb.ReportOptions {
	cats := []abuseipdb.ReportCategory{}
	for _, c := range report.Categories {
		switch c {
		case "DnsCompromise":
			cats = append(cats, abuseipdb.DnsCompromise)
		case "DnsPoisoning":
			cats = append(cats, abuseipdb.DnsPoisoning)
		case "FraudOrders":
			cats = append(cats, abuseipdb.FraudOrders)
		case "DDoSAttack":
			cats = append(cats, abuseipdb.DDoSAttack)
		case "FtpBruteForce":
			cats = append(cats, abuseipdb.FtpBruteForce)
		case "PingOfDeath":
			cats = append(cats, abuseipdb.PingOfDeath)
		case "Phishing":
			cats = append(cats, abuseipdb.Phishing)
		case "FraudVoIp":
			cats = append(cats, abuseipdb.FraudVoIp)
		case "OpenProxy":
			cats = append(cats, abuseipdb.OpenProxy)
		case "WebSpam":
			cats = append(cats, abuseipdb.WebSpam)
		case "EmailSpam":
			cats = append(cats, abuseipdb.EmailSpam)
		case "BlogSpam":
			cats = append(cats, abuseipdb.BlogSpam)
		case "VpnIp":
			cats = append(cats, abuseipdb.VpnIp)
		case "PortScan":
			cats = append(cats, abuseipdb.PortScan)
		case "Hacking":
			cats = append(cats, abuseipdb.Hacking)
		case "SqlInjection":
			cats = append(cats, abuseipdb.SqlInjection)
		case "Spoofing":
			cats = append(cats, abuseipdb.Spoofing)
		case "BruteForce":
			cats = append(cats, abuseipdb.BruteForce)
		case "BadWebBot":
			cats = append(cats, abuseipdb.BadWebBot)
		case "ExploitedHost":
			cats = append(cats, abuseipdb.ExploitedHost)
		case "WebAppAttack":
			cats = append(cats, abuseipdb.WebAppAttack)
		case "Ssh":
			cats = append(cats, abuseipdb.Ssh)
		case "IotTargeted":
			cats = append(cats, abuseipdb.IotTargeted)
		}
	}
	return &abuseipdb.ReportOptions{
		Categories: cats,
		Comment:    report.Comment,
		Time:       &report.Timestamp,
	}
}

func (r *AbuseIPDBReporter) reporter() {
	for report := range r.ch {
		if r.client != nil {
			if *reportTestIPOnly {
				report.IP = net.IPv4(127, 0, 0, 2)
			}
			ro := r.makeOptions(report)
			log.Printf("reporting: %v %v", report, ro)
			result, err := r.client.Report(context.Background(), report.IP, ro)
			if err != nil {
				log.Printf("Error reporting to AbuseIPDB: %v", err)
			} else {
				log.Printf("AbuseIPDB response: IP=%s, confidence=%d",
					result.Data.IpAddress, result.Data.AbuseConfidenceScore)
			}
		}
	}
}

func (rep *AbuseIPDBReporter) SiteVerificationHandler() (string, http.HandlerFunc) {
	if rep.siteVerificationToken == "" {
		return "", func(http.ResponseWriter, *http.Request) {}
	}
	return "/abuseipdb-verification.html", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(rep.siteVerificationToken))
	}
}

func NewAbuseIPDBReporter(apikey, siteVerificationToken string) *AbuseIPDBReporter {
	client := abuseipdb.NewClient(nil)
	client.AddApiKey(apikey)
	limit := rate.Every(5 * time.Second)
	return &AbuseIPDBReporter{
		client:                client,
		siteVerificationToken: siteVerificationToken,
		limiter:               rate.NewLimiter(limit, 10),
		reportCache:           expirable.NewLRU[AbuseIPDBReportCacheKey, bool](512, nil, 30*time.Minute),
	}
}

// LogOnlyReporter just observes report calls.  Mostly for testing.
type LogOnlyReporter struct {
	Reports chan string
}

func (r *LogOnlyReporter) Report(report *Report) error {
	log.Printf("pretending to report: %v", report)
	r.Reports <- fmt.Sprintf("%s %d %q %q", report.IP, report.Timestamp.Unix(), report.Categories, report.Comment)
	return nil
}

func NewLogOnlyReporter(reports chan string) *LogOnlyReporter {
	return &LogOnlyReporter{Reports: reports}
}

func (r *LogOnlyReporter) SiteVerificationHandler() (string, http.HandlerFunc) {
	return "", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("pretending to handle site verification on %q", r.URL.Path)
	}
}
