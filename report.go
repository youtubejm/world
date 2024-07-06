package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

func main() {
	report, err := net.Listen("tcp", "0.0.0.0:199")
	if err != nil {
		fmt.Println(err)
		return
	}

	defer report.Close()

	fmt.Println("- Killer Report server listening on: 199")

	for {
		conn, err := report.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	buffer := make([]byte, 1024)

	for {
		n, err := reader.Read(buffer)
		if err != nil {
			fmt.Println(err)
			break
		}

		if n > 0 {
			currentTime := time.Now().Format("2006-01-02 15:04:05")
			message := string(buffer[:n])

			var msgType string
			if strings.Contains(message, "Killed") {
				msgType = "killer"
			} else if strings.Contains(message, "locked") {
				msgType = "locker"
			} else {
				msgType = "unknown"
			}

			output := fmt.Sprintf("\x1b[31m%s\x1b[0m | [\x1b[5m\x1b[31m%s\x1b[25m\x1b[0m] %s", currentTime, msgType, message[:min(len(message), 100)])
			fmt.Println(output)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// fixed memleak cak3
