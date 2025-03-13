package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/aqua/nothingofvalue"
	"github.com/aqua/nothingofvalue/reporter"
)

var listenAddr = flag.String("listen", "", "[address]:port to listen on")
var abuseipdbVerificationToken = flag.String("abuseip-verification-token", "", "Site verification token for AbuseIPDB reporting")
var abuseipdbAPIKey = flag.String("abuseip-api-key", "", "AbuseIPDB API key")
var abuseipdbEnable = flag.Bool("enable-abuseipdb", false, "Report abusive calls to AbuseIPDB")

func main() {
	flag.Parse()
	addr := ":" + os.Getenv("PORT")
	if *listenAddr != "" {
		addr = *listenAddr
	} else if addr == ":" {
		addr = "localhost:8080"
	}
	handler := nothingofvalue.NewHandler()
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}
	if *abuseipdbEnable {
		log.Printf("enabling AbuseIPDB (token %q)", *abuseipdbVerificationToken)
		handler.AddReporter(reporter.NewAbuseIPDBReporter(*abuseipdbAPIKey, *abuseipdbVerificationToken))
	} else {
		log.Printf("not enabling AbuseIPDB")
	}
	log.Printf("listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
