package tss

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func ListenForPeer(id, pubkey, port, timeout string) (string, error) {
	Logln("BBMTLog", "listening for peer...")

	// Channel to capture the peer IP
	peerFound := make(chan string)

	// HTTP handler to detect peer IP
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			Logln("BBMTLog", "error getting client IP:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		Logf("BBMTLog: got a peer connection from %s\n", clientIP)
		srcIP := r.URL.Query().Get("src")
		dstIP := r.URL.Query().Get("dst")
		srcId := r.URL.Query().Get("id")
		srcPubkey := r.URL.Query().Get("pubkey")
		if srcIP != "" && dstIP != "" && srcPubkey != "" {
			go func() {
				client := http.Client{
					Timeout: 2 * time.Second,
				}
				srcIP, _, _ := net.SplitHostPort(r.RemoteAddr)
				url := "http://" + srcIP + ":" + port + "/?src=" + dstIP + "&dst=" + srcIP + "&id=" + id + "&pubkey=" + pubkey
				Logln("BBMTLog", "Sending callback to:", url)
				_, err = client.Get(url)
				if err != nil {
					Logln("BBMTLog", "Error in callback:", err)
				}
			}()
			peerFound <- (clientIP + "@" + srcId + "@" + srcPubkey + "," + dstIP + "@" + id + "@" + pubkey)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, dstIP+"@"+id+"@"+pubkey+","+clientIP+"@"+srcId+"@"+srcPubkey)
	})

	if server != nil {
		StopRelay()
	}

	server := &http.Server{Addr: "0.0.0.0:" + port, Handler: mux}

	go func() {
		Logln("BBMTLog", "Waiting for peer connection on port:", port, ", timeout:", timeout)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			Logln("HTTP server error:", err)
		}
	}()

	tout, err := strconv.Atoi(timeout)
	if err != nil {
		tout = 30
	}

	select {
	case peerIP := <-peerFound:
		Logln("BBMTLog", "Peer detected, shutting down server...")
		time.Sleep(2000)
		StopRelay()
		return peerIP, nil
	case <-time.After(time.Duration(tout) * time.Second):
		Logln("BBMTLog", "Timeout reached, shutting down server...")
		StopRelay()
		return "", fmt.Errorf("timeout waiting for peer connection")
	}
}

func DiscoverPeer(id, pubkey, localIP, remoteIP, port, timeout string) (string, error) {
	if localIP == "" {
		return "", fmt.Errorf("no local IP detected, skipping peer discovery")
	}

	baseIP := localIP[:strings.LastIndex(localIP, ".")+1]
	peerFound := make(chan string)
	tout, err := strconv.Atoi(timeout)
	if err != nil {
		tout = 30
	}
	if tout < 5 {
		tout = 5
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(tout)*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 2000 * time.Millisecond}

	// Function to check a given IP
	checkPeer := func(ip string) {
		select {
		case <-ctx.Done():
			return
		default:
			url := "http://" + ip + "/?src=" + localIP + "&dst=" + ip + "&id=" + id + "&pubkey=" + pubkey
			resp, err := client.Get(url)
			if err == nil && resp.StatusCode == http.StatusOK {
				Logf("Peer discovered at: %s\n", ip)
				bodyBytes, err := io.ReadAll(resp.Body)
				if err == nil {
					peerFound <- string(bodyBytes)
					cancel() // Cancel all other goroutines if a peer is found
				}
			}
		}
	}

	// First, check remoteIP if provided
	if remoteIP != "" && remoteIP != localIP {
		checkPeer(fmt.Sprintf("%s:%s", remoteIP, port))
	}

	// Scan the local subnet
	for i := 1; i <= 254; i++ {
		targetIP := fmt.Sprintf("%s%d", baseIP, i)
		if targetIP == localIP {
			Logln("BBMTLog", "skip self peer")
			continue
		}
		go checkPeer(fmt.Sprintf("%s:%s", targetIP, port))
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case peerIP := <-peerFound:
		return peerIP, nil
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("peer discovery timed out after %d seconds", tout)
		}
		return "", fmt.Errorf("peer discovery stopped")
	}
}

func FetchData(url, decKey string) (string, error) {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	Logln("BBMTLog", "checking for peer connection:", url)
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("error getting data: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error getting data: status code %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	decryptedData, err := EciesDecrypt(string(bodyBytes), decKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt chaincode: %w", err)
	}
	Logln("data decrypted successfully")
	return decryptedData, nil
}

func PublishData(port, timeout, enckey, data string) (string, error) {
	Logln("BBMTLog", "publishing data...")
	published := make(chan string)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		encryptedData, err := EciesEncrypt(data, enckey)
		if err != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			Logln("BBMTLog", "error publishing:", err)
			published <- "error"
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, encryptedData)
		published <- "ok"
	})

	if server != nil {
		StopRelay()
	}
	time.Sleep(time.Second)
	server = &http.Server{Addr: "0.0.0.0:" + port, Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			Logln("HTTP server error:", err)
		}
	}()
	tout, err := strconv.Atoi(timeout)
	if err != nil {
		tout = 30
	}
	select {
	case isOk := <-published:
		Logln("BBMTLog", "published", isOk)
		time.Sleep(1000)
		StopRelay()
		return isOk, nil
	case <-time.After(time.Duration(tout) * time.Second):
		Logln("BBMTLog", "Timeout reached, shutting down server...")
		StopRelay()
		return "", fmt.Errorf("timeout waiting for peer connection")
	}
}
