package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/aqua/nothingofvalue"
)

var listenAddr = flag.String("listen", "", "[address]:port to listen on")

func main() {
	flag.Parse()
	addr := ":" + os.Getenv("PORT")
	if *listenAddr != "" {
		addr = *listenAddr
	} else if addr == ":" {
		addr = "localhost:8080"
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: nothingofvalue.NewHandler(),
	}
	log.Printf("listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
