package ftp

import (
	"http-webserver/core/ftp/filedriver"
	"http-webserver/core/ftp/server"
	"log"
)

func Serve(port int) {
	var perm = server.NewSimplePerm("root", "root")
	opt := &server.ServerOpts{
		Factory: &filedriver.FileDriverFactory{
			RootPath: "./static/",
			Perm:     perm,
		},
		Hostname: "",
		Port:     port,
		Auth:     &server.NoAuth{},
		Logger:   new(server.DiscardLogger),
	}

	log.Printf("[ftp] Server listening on port %d\n", port)
	s := server.NewServer(opt)
	err := s.ListenAndServe()
	if err != nil {
		return
	}

}
