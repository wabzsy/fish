package main

import (
	"fish"
	"flag"
	"log"
)

func main() {
	addr := flag.String("a", ":22", "ssh server listen addr")
	flag.Parse()

	srv, err := fish.NewServer(*addr)
	if err != nil {
		log.Fatalln(err)
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalln(err)
	}
}
