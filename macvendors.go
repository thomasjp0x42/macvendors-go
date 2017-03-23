package main

import (
	"crypto/tls"
	"encoding/csv"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uber-go/zap"

	_ "net/http/pprof"
)

var downloadDirectory = "/tmp/"

// Map out the different CSV files we need to download and import
var csvs = struct {
	m map[string]string
}{m: map[string]string{
	"mal": "https://standards.ieee.org/develop/regauth/oui/oui.csv",
	"mam": "https://standards.ieee.org/develop/regauth/oui28/mam.csv",
	"mas": "https://standards.ieee.org/develop/regauth/oui36/oui36.csv",
}}

var addressMap = struct {
	sync.RWMutex
	m map[string]string
}{m: map[string]string{
// To be loaded....
}}

var logger = zap.New(
	zap.NewJSONEncoder(),
)

func main() {
	// Load data when app first opens
	loadData()

	// Set ticker to refresh data every 6 hours
	ticker := time.NewTicker(time.Hour * 6)
	go func() {
		for range ticker.C {
			loadData()
		}
	}()

	go spawnServer80()
	spawnServer443()

}

func spawnServer80() {
	mux := http.NewServeMux()

	mux.HandleFunc("/favicon.ico", dropRequest)
	mux.HandleFunc("/", processHTTP)

	server := &http.Server{
		Addr:         ":80",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	logger.Fatal(server.ListenAndServe().Error())
}

func spawnServer443() {
	muxSSL := http.NewServeMux()

	muxSSL.HandleFunc("/favicon.ico", dropRequest)
	muxSSL.HandleFunc("/", processHTTPS)

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	serverSSL := &http.Server{
		Addr:         ":443",
		Handler:      muxSSL,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	logger.Fatal(serverSSL.ListenAndServeTLS("/etc/letsencrypt/live/api.macvendors.com/fullchain.pem", "/etc/letsencrypt/live/api.macvendors.com/privkey.pem").Error())
}

func dropRequest(w http.ResponseWriter, r *http.Request) {}

func processHTTP(w http.ResponseWriter, r *http.Request) {
	process(w, r, "http")
}
func processHTTPS(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	process(w, r, "https")
}

// Processes the HTTP request
func process(w http.ResponseWriter, r *http.Request, connectionType string) {

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-type", "text/plain")

	var macAddress string
	var response string

	clientIP, _, netSplitErr := net.SplitHostPort(r.RemoteAddr)

	if netSplitErr != nil {

		logger.Error(netSplitErr.Error())
		http.Error(w, "Invalid host IP/PORT", http.StatusBadRequest)
		return
	}

	if r.Method == "GET" {
		macAddress = r.URL.Path[1:]
	} else {
		http.Error(w, r.Method+" requests not accepted", http.StatusMethodNotAllowed)
		return
	}

	if macAddress == "" {
		http.Error(w, "No MAC address provided", http.StatusBadRequest)
		return
	}

	cleanedMacAddress := cleanMacAddress(macAddress)
	cleanedAddressLength := len(cleanedMacAddress)

	var vendor string

	addressMap.RLock()
	defer addressMap.RUnlock()

	if cleanedAddressLength >= 9 {
		// Check for MA-S match
		if val, ok := addressMap.m[cleanedMacAddress[0:9]]; ok {
			vendor = val
		}
	}

	if vendor == "" && cleanedAddressLength >= 7 {
		// Check for MA-M match
		if val, ok := addressMap.m[cleanedMacAddress[0:7]]; ok {
			vendor = val
		}
	}

	if vendor == "" && cleanedAddressLength >= 6 {
		// Check for MA-L match
		if val, ok := addressMap.m[cleanedMacAddress[0:6]]; ok {
			vendor = val
		}
	}

	if vendor != "" {
		io.WriteString(w, vendor)
		response = vendor
	} else {
		http.Error(w, "Vendor not found", http.StatusNotFound)
		response = "Not Found"
	}

	logger.Info(
		"api request",
		zap.String("clientIp", clientIP),
		zap.String("connectionType", connectionType),
		zap.String("method", r.Method),
		zap.String("macAddress", cleanedMacAddress),
		zap.String("response", response),
	)

}

// Take macAddress as a string and prepare it for lookup.
// Return value will be alphanumeric, lower case and a max length of 12 characters
func cleanMacAddress(macAddress string) string {
	reg, err := regexp.Compile("[^A-Za-z0-9]+")
	if err != nil {
		logger.Error(err.Error())
	}

	cleanedMacAddress := strings.ToLower(strings.TrimSpace(reg.ReplaceAllString(macAddress, "")))

	if len(cleanedMacAddress) > 12 {
		cleanedMacAddress = cleanedMacAddress[0:12]
	}

	return cleanedMacAddress
}

// Fuction to download and load the various CSV files
func loadData() {
	logger.Info("Initating Vendor Refresh")
	purgeCSVS()
	downloadFiles()
	loadCSV()
	purgeCSVS()
	logger.Info("Vendor Refresh Complete")
}

func purgeCSVS() {
	for listName := range csvs.m {
		file := listName + ".csv"
		filePath := downloadDirectory + file
		os.Remove(filePath)
	}
}

// Loop through csvs struct and download each file
func downloadFiles() {
	for listName, value := range csvs.m {

		file := listName + ".csv"

		filePath := downloadDirectory + file

		logger.Info("Downloading " + file)

		results := downloadFile(filePath, value)

		if results != nil {
			logger.Error(results.Error())
		} else {
			logger.Info("Download " + file + " complete")
		}
	}
}

// Download file
func downloadFile(filepath string, url string) (err error) {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("Unable to download file. HTTP StatusCode: " + strconv.Itoa(resp.StatusCode) + " (" + url + ")")
	}

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	defer resp.Body.Close()

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

// Loop throuh downloaded csvs and load into map
func loadCSV() {
	for listName := range csvs.m {

		file := listName + ".csv"

		filePath := downloadDirectory + file

		logger.Info("Parsing " + file)

		results := parseCSV(filePath)

		if results == nil {
			logger.Info("Parsing " + file + " complete")
		} else {
			logger.Error(results.Error())
		}

	}
}

// Open CSV and loop through it, loading the values into addressMap
func parseCSV(csvFilePath string) error {
	csvFile, err := os.Open(csvFilePath)

	if err != nil && os.IsNotExist(err) {
		return errors.New(csvFilePath + " does not exist")
	} else if err != nil && os.IsPermission(err) {
		return errors.New("Can not open " + csvFilePath + " due to invalid file permissions")
	}

	defer csvFile.Close()

	reader := csv.NewReader(csvFile)

	for {
		record, err := reader.Read()

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		address := strings.ToLower(strings.TrimSpace(record[1]))
		vendor := strings.TrimSpace(record[2])

		addressMap.Lock()
		addressMap.m[address] = vendor
		addressMap.Unlock()

	}

	return nil
}
