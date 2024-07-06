package tftp

import (
	"errors"
	"github.com/pin/tftp"
	"io"
	"log"
	"os"
	"path/filepath"
)

var (
	staticDir = "./static/"
)

func Serve() {
	server := tftp.NewServer(func(filename string, rf io.ReaderFrom) error {
		raddr := rf.(tftp.OutgoingTransfer).RemoteAddr()

		file, err := os.Open(filepath.Join(staticDir, filename))
		if err != nil {
			return errors.New("file not found")
		}

		defer file.Close()

		_, err = rf.ReadFrom(file)
		if err != nil {
			return err
		}

		log.Printf("[tftp] %s requested %s\n", raddr.IP.String(), filename)

		return nil
	}, nil)

	log.Printf("[tftp] Server listening on port 69\n")
	err := server.ListenAndServe(":69")
	if err != nil {
		return
	}
}
