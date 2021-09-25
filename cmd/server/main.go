package main

import (
	"log"

	"github.com/andresmijares/go-distributed/internal/server"
)

func main() {
	srv := server.NewHTTPServer(":8080")
	log.Fatal(srv.ListenAndServe())
}
