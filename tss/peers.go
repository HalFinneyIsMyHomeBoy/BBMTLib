package tss

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func ListenForPeer(id, pubkey, port, timeout string) (string, error) {
	log.Println("BBMTLog", "listening for peer...")

	// Channel to capture the peer IP
	peerFound := make(chan string)

	// HTTP handler to detect peer IP
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Println("BBMTLog", "error getting client IP:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		log.Printf("BBMTLog: got a peer connection from %s\n", clientIP)
		srcIP := r.URL.Query().Get("src")
		dstIP := r.URL.Query().Get("dst")
		srcId := r.URL.Query().Get("id")
		srcPubkey := r.URL.Query().Get("pubkey")
		if srcIP != "" && dstIP != "" && srcPubkey != "" {
			go func() {
				client := http.Client{
					Timeout: 5 * time.Second,
				}
				url := "http://" + srcIP + ":" + port + "/?src=" + dstIP + "&dst=" + srcIP + "&id=" + id + "&pubkey=" + pubkey
				log.Println("BBMTLog", "Sending callback to:", url)
				_, err := client.Get(url)
				if err != nil {
					log.Println("BBMTLog", "Error in callback:", err)
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
	time.Sleep(time.Second)
	server := &http.Server{Addr: "0.0.0.0:" + port, Handler: mux}

	go func() {
		log.Println("BBMTLog", "Waiting for peer connection on port:", port, ", timeout:", timeout)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Println("HTTP server error:", err)
		}
	}()

	tout, err := strconv.Atoi(timeout)
	if err != nil {
		tout = 30
	}

	select {
	case peerIP := <-peerFound:
		log.Println("BBMTLog", "Peer detected, shutting down server...")
		_ = server.Close()
		return peerIP, nil
	case <-time.After(time.Duration(tout) * time.Second):
		log.Println("BBMTLog", "Timeout reached, shutting down server...")
		_ = server.Close()
		return "", fmt.Errorf("timeout waiting for peer connection")
	}
}

func DiscoverPeer(id, pubkey, localIP, port, timeout string) (string, error) {
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
	for i := 1; i <= 254; i++ {
		targetIP := fmt.Sprintf("%s%d:%s", baseIP, i, port)
		if localIP == fmt.Sprintf("%s%d", baseIP, i) {
			log.Println("BBMTLog", "skip self peer")
			continue
		}
		go func(ip string) {
			select {
			case <-ctx.Done():
				return // If context is done (timeout or peer found), return early
			default:
				client := &http.Client{Timeout: 2000 * time.Millisecond}
				url := "http://" + ip + "/?src=" + localIP + "&dst=" + ip + "&id=" + id + "&pubkey=" + pubkey
				log.Println("BBMTLog", "checking for peer connection:", url)
				resp, err := client.Get(url)
				if err == nil && resp.StatusCode == http.StatusOK {
					fmt.Printf("Peer discovered at: %s\n", ip)
					bodyBytes, err := io.ReadAll(resp.Body)
					if err == nil {
						peerFound <- string(bodyBytes)
						cancel() // Cancel all other goroutines if a peer is found
					}
				} else {
					log.Println("BBMTLog", "Peer not available at:", ip)
				}
			}
		}(targetIP)
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
	log.Println("BBMTLog", "checking for peer connection:", url)
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
	log.Println("data decrypted successfully")
	return decryptedData, nil
}

func PublishData(port, timeout, enckey, data string) (string, error) {
	log.Println("BBMTLog", "publishing data...")
	published := make(chan string)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		encryptedData, err := EciesEncrypt(data, enckey)
		if err != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			log.Println("BBMTLog", "error publishing:", err)
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
	server := &http.Server{Addr: "0.0.0.0:" + port, Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Println("HTTP server error:", err)
		}
	}()
	tout, err := strconv.Atoi(timeout)
	if err != nil {
		tout = 30
	}
	select {
	case isOk := <-published:
		log.Println("BBMTLog", "published", isOk)
		_ = server.Close()
		return isOk, nil
	case <-time.After(time.Duration(tout) * time.Second):
		log.Println("BBMTLog", "Timeout reached, shutting down server...")
		_ = server.Close()
		return "", fmt.Errorf("timeout waiting for peer connection")
	}
}
