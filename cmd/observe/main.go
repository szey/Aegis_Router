package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/szey/Aegis_Router/internal/sessionaudit"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("observe", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	auditPath := flags.String("audit", filepath.Join("data", "session-audit.jsonl"), "append-only normalized audit path")
	sessionID := flags.String("session", fmt.Sprintf("local-%d", time.Now().UnixNano()), "Aegis_Router correlation session ID")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	command := flags.Args()
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "usage: observe [--audit path] [--session id] -- <command> [args...]")
		return 2
	}

	recorder, err := sessionaudit.New(*auditPath, *sessionID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create recorder:", err)
		return 1
	}
	closed := false
	closeRecorder := func() {
		if !closed {
			if err := recorder.Close(); err != nil {
				fmt.Fprintln(os.Stderr, "close recorder:", err)
			}
			closed = true
		}
	}
	defer closeRecorder()

	executable := filepath.Base(command[0])
	_, err = recorder.RecordLifecycle("process.starting", "starting", []string{
		"executable=" + executable,
		"arguments_sha256=" + sessionaudit.HashArguments(command[1:]),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "record start:", err)
		return 1
	}

	child := exec.Command(command[0], command[1:]...)
	child.Stdin = os.Stdin
	child.Stderr = os.Stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "capture stdout:", err)
		return 1
	}
	if err := child.Start(); err != nil {
		_, _ = recorder.RecordLifecycle("process.start_failed", "failed", []string{"error=" + err.Error()})
		fmt.Fprintln(os.Stderr, "start child:", err)
		return 1
	}
	_, _ = recorder.RecordLifecycle("process.started", "running", []string{fmt.Sprintf("pid=%d", child.Process.Pid)})

	scanErr := stream(stdout, os.Stdout, recorder)
	waitErr := child.Wait()
	status, exitCode := "completed", 0
	if waitErr != nil {
		status = "failed"
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	_, recordErr := recorder.RecordLifecycle("process.exited", status, []string{fmt.Sprintf("exit_code=%d", exitCode)})
	closeRecorder()
	if scanErr != nil {
		fmt.Fprintln(os.Stderr, "read child output:", scanErr)
		return 1
	}
	if recordErr != nil {
		fmt.Fprintln(os.Stderr, "record exit:", recordErr)
		return 1
	}
	return exitCode
}

func stream(reader io.Reader, output io.Writer, recorder *sessionaudit.Recorder) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if _, err := fmt.Fprintln(output, string(line)); err != nil {
			return err
		}
		if _, err := recorder.RecordJSONLine(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}
