package main

import (
	"context"
	"encoding/base64"
	b64 "encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
)

func test1() {
	data := "cHdk"
	sDec, _ := b64.StdEncoding.DecodeString(data)
	// ruleid: go-exec-base64
	cmd := exec.Command(string(sDec))
	_, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

func test2() {
	data := "bHM="
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))

	decoded, err := io.ReadAll(decoder)
	if err != nil {
		fmt.Println("Decode error:", err)
		return
	}

	// ruleid: go-exec-base64
	cmd := exec.Command(string(decoded))
	_, err = cmd.Output()

	if err != nil {
		fmt.Println("Command error:", err)
		return
	}
}

func test3() {
	data := "d2hvYW1p"
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	n, err := base64.StdEncoding.Decode(dst, []byte(data))
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}

	decoded := dst[:n]
	cmdPath, _ := exec.LookPath("bash")

	// ruleid: go-exec-base64
	cmd := &exec.Cmd{
		Path:   cmdPath,
		Args:   []string{cmdPath, "-c", string(decoded)},
		Stdout: os.Stdout,
		Stderr: os.Stdout,
	}
	cmd.Start()
}

func test4() {
	data := "d2hvYW1p"
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	n, err := base64.StdEncoding.Decode(dst, []byte(data))
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}
	decoded := dst[:n]

	// ruleid: go-exec-base64
	cmd := exec.Command(string(decoded))
	_, err = cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

func test5() {
	data := "cHdk"
	sDec, _ := b64.StdEncoding.DecodeString(data)
	cmdPath, _ := exec.LookPath("bash")

	// ruleid: go-exec-base64
	cmd := &exec.Cmd{
		Path:   cmdPath,
		Args:   []string{cmdPath, "-c", string(sDec)},
		Stdout: os.Stdout,
		Stderr: os.Stdout,
	}
	cmd.Start()
}

func test6() {
	data := "bHM="

	decoded, err := base64.StdEncoding.AppendDecode(nil, []byte(data))
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}

	// ruleid: go-exec-base64
	cmd := exec.Command(string(decoded))
	_, err = cmd.Output()
	if err != nil {
		fmt.Println("command error:", err)
		return
	}
}

func test7() {
	decodeFunc := reflect.ValueOf(base64.StdEncoding.DecodeString)

	args := []reflect.Value{reflect.ValueOf("cHdk")}
	results := decodeFunc.Call(args)

	decoded := results[0].Interface().([]byte)

	// ruleid: go-exec-base64
	cmd := exec.Command(string(decoded))
	_, err := cmd.Output()
	if err != nil {
		fmt.Println("command error:", err)
		return
	}
}

func test8() {
	data := "cHdk"
	sDec, _ := b64.StdEncoding.DecodeString(data)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ruleid: go-exec-base64
	cmd := exec.CommandContext(ctx, string(sDec))
	_, _ = cmd.Output()
}

func test9() {
	data := "L2Jpbi9wd2Q="
	sDec, _ := b64.StdEncoding.DecodeString(data)

	procAttr := &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}
	// ruleid: go-exec-base64
	proc, _ := os.StartProcess(string(sDec), []string{string(sDec)}, procAttr)
	_, _ = proc.Wait()
}

func test10() {
	data := "L29wdC9ob21lYnJldy9vcHQvY29yZXV0aWxzL2xpYmV4ZWMvZ251YmluL3RvdWNoIHRlc3RfZmlsZV83"
	sDec, _ := b64.StdEncoding.DecodeString(data)
	parts := strings.Fields(string(sDec))
	env := os.Environ()
	// ruleid: go-exec-base64
	_ = syscall.Exec(parts[0], parts, env)
}

func test11() {
	data := "L29wdC9ob21lYnJldy9vcHQvY29yZXV0aWxzL2xpYmV4ZWMvZ251YmluL3RvdWNoIHRlc3RfZmlsZQ=="
	sDec, _ := b64.StdEncoding.DecodeString(data)
	cmdParts := strings.Fields(string(sDec))
	if len(cmdParts) == 0 {
		fmt.Println("No command to execute")
		return
	}
	env := os.Environ()

	// ruleid: go-exec-base64
	_, err := syscall.ForkExec(cmdParts[0], cmdParts, &syscall.ProcAttr{
		Env:   env,
		Dir:   ".",
		Files: []uintptr{0, 1, 2},
	})
	if err != nil {
		fmt.Println("ForkExec failed:", err)
		return
	}
}

func test12() {
	data := "cHdk"
	sDec, _ := base64.RawStdEncoding.DecodeString(data)
	// ruleid: go-exec-base64
	cmd := exec.Command(string(sDec))
	_, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

func test13() {
	data := "cHdk"
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	n, err := base64.RawStdEncoding.Decode(dst, []byte(data))
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}

	decoded := dst[:n]
	cmdPath, _ := exec.LookPath("bash")
	// ruleid: go-exec-base64
	cmd := &exec.Cmd{
		Path:   cmdPath,
		Args:   []string{cmdPath, "-c", string(decoded)},
		Stdout: os.Stdout,
		Stderr: os.Stdout,
	}
	cmd.Start()
}

func test14() {
	encoded := "cHdk"
	newDecoderFunc := reflect.ValueOf(base64.NewDecoder)
	args := []reflect.Value{
		reflect.ValueOf(base64.StdEncoding),
		reflect.ValueOf(strings.NewReader(encoded)),
	}
	results := newDecoderFunc.Call(args)
	reader := results[0].Interface().(io.Reader)
	decoded := make([]byte, 100)
	n, err := reader.Read(decoded)
	if err != nil && err != io.EOF {
		fmt.Println("decode error:", err)
		return
	}
	// ruleid: go-exec-base64
	cmd := exec.Command(string(decoded[:n]))
	_, err = cmd.Output()
	if err != nil {
		fmt.Println("command error:", err)
		return
	}
}

func test15() {
	encoded := []byte("cHdk")
	dst := make([]byte, 0, base64.StdEncoding.DecodedLen(len(encoded)))
	appendDecodeFunc := reflect.ValueOf(base64.StdEncoding.AppendDecode)
	args := []reflect.Value{
		reflect.ValueOf(dst),
		reflect.ValueOf(encoded),
	}
	results := appendDecodeFunc.Call(args)
	decoded := results[0].Interface().([]byte)

	// ruleid: go-exec-base64
	cmd := exec.Command(string(decoded))
	_, err := cmd.Output()
	if err != nil {
		fmt.Println("command error:", err)
		return
	}
}

func test16() {
	data := []byte("cHdk")
	dst := make([]byte, base64.RawStdEncoding.DecodedLen(len(data)))
	decodeFunc := reflect.ValueOf(base64.RawStdEncoding.Decode)

	args := []reflect.Value{
		reflect.ValueOf(dst),
		reflect.ValueOf(data),
	}

	results := decodeFunc.Call(args)
	n := results[0].Interface().(int)
	errInterface := results[1].Interface()
	if errInterface != nil {
		fmt.Println("decode error:", errInterface)
		return
	}
	decoded := dst[:n]
	cmdPath, _ := exec.LookPath("bash")
	// ruleid: go-exec-base64
	cmd := &exec.Cmd{
		Path:   cmdPath,
		Args:   []string{cmdPath, "-c", string(decoded)},
		Stdout: os.Stdout,
		Stderr: os.Stdout,
	}
	cmd.Start()
}

func test17() {
	// ok: go-exec-base64
	cmd := exec.Command("ls", "-la")
	cmd.Run()
}

func test18() {
	binary := "/bin/echo"
	args := []string{"echo", "This is safe"}
	env := os.Environ()
	// ok: go-exec-base64
	syscall.Exec(binary, args, env)
}

func test19() {
	argv := []string{"sh", "-c", "echo 'safe command'"}
	env := os.Environ()
	// ok: go-exec-base64
	os.StartProcess("/bin/sh", argv, &os.ProcAttr{Env: env, Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}})
}

func test20() {
	encoded := "SGVsbG8sIHdvcmxkIQ=="
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		fmt.Println("Error decoding:", err)
		return
	}
	// ok: go-exec-base64
	fmt.Println("Decoded string:", string(decoded))
}
