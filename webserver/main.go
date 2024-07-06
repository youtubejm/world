package main

import (
	"http-webserver/core/ftp"
	"http-webserver/core/http"
	"http-webserver/core/tftp"
)

func main() {
	go tftp.Serve()
	go ftp.Serve(21)
	go ftp.Serve(8021)
	go http.Serve2()
	http.Serve()
}
