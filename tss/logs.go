package tss

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type GoLogListener interface {
	OnGoLog(message string)
}

var logDisabled bool
var goLogListener GoLogListener

// Preserve original outputs so we can re-enable logs after DisableLogs
var originalStdout *os.File = os.Stdout
var originalStderr *os.File = os.Stderr

// SetEventListener sets the listener for UTXO events
func SetEventListener(l GoLogListener) {
	goLogListener = l
}

type nullWriter struct{}

func (nw nullWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func EnableLogs() {
	logDisabled = false
	os.Stdout = originalStdout
	os.Stderr = originalStderr
	InitLog()
}

func DisableLogs() {
	logDisabled = true
	goLogListener = nil
	nullFile, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %s: %v\n", os.DevNull, err)
		os.Exit(1)
	}
	defer nullFile.Close()
	// Redirect output
	os.Stdout = nullFile
	os.Stderr = nullFile
	log.SetOutput(nullWriter{})
}

// EnableStdout restores stdout/stderr and re-initializes the logger
func Stdout(out any) {
	if logDisabled {
		// Restore standard outputs
		if originalStdout != nil {
			os.Stdout = originalStdout
		}
		fmt.Println(out)
		DisableLogs()
	} else {
		fmt.Println(out)
	}
}

// EnableStdout restores stdout/stderr and re-initializes the logger
func Stderr(out any) {
	if logDisabled {
		// Restore standard outputs
		if originalStderr != nil {
			os.Stderr = originalStderr
		}
		fmt.Fprintln(os.Stderr, out)
		// revert standard outputs
		DisableLogs()
	} else {
		fmt.Fprintln(os.Stderr, out)
	}
}

// Function to send logs to React Native
func logToReactNative(message string) {
	if goLogListener != nil {
		goLogListener.OnGoLog(message)
	}
}

// Logf function: formats message and logs it
func Logf(format string, v ...any) {
	if !logDisabled {
		msg := fmt.Sprintf(format, v...) // Format the message
		logToReactNative(msg)            // Send to React Native
		fmt.Println(msg)                 // Also log to Logcat
		log.Println(msg)
	}
}

// Logln: Logs a message like fmt.Println
func Logln(v ...any) {
	if !logDisabled {
		msg := strings.TrimSpace(fmt.Sprintln(v...))
		logToReactNative(msg)
		fmt.Println(v...)
		log.Println(v...)
	}
}

func InitLog() {
	log.SetFlags(0)
	log.SetOutput(logWriter{})
}

type logWriter struct{}

func (logWriter) Write(p []byte) (n int, err error) {
	logToReactNative(string(p))
	return len(p), nil
}
