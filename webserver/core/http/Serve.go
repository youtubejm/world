package http

import (
	"log"
	"net/http"
	"path/filepath"
)

func Serve() {
	staticDir := "./static"

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) < 2 {
			http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
			return
		}

		log.Printf("[http] %s requested %s\r\n", r.RemoteAddr, r.URL.Path)
		http.ServeFile(w, r, filepath.Join(staticDir, r.URL.Path))
	})

	log.Println("[http] Server listening on port 80")
	log.Fatal(http.ListenAndServe(":80", nil))
}
func Serve2() {
	log.Println("[http] Server listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
