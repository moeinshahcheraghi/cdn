// Package logx is a tiny leveled logger so both binaries log consistently
// without pulling in a dependency.
package logx

import (
	"fmt"
	"os"
	"time"
)

// Level controls verbosity.
type Level int32

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

var current = LevelInfo

// SetLevel sets the global log level from a name (error/warn/info/debug).
func SetLevel(name string) {
	switch name {
	case "error":
		current = LevelError
	case "warn":
		current = LevelWarn
	case "debug":
		current = LevelDebug
	default:
		current = LevelInfo
	}
}

func logf(l Level, tag, format string, args ...any) {
	if l > current {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "%s %s %s\n", ts, tag, fmt.Sprintf(format, args...))
}

// Errorf logs at error level.
func Errorf(format string, args ...any) { logf(LevelError, "ERR ", format, args...) }

// Warnf logs at warn level.
func Warnf(format string, args ...any) { logf(LevelWarn, "WARN", format, args...) }

// Infof logs at info level.
func Infof(format string, args ...any) { logf(LevelInfo, "INFO", format, args...) }

// Debugf logs at debug level.
func Debugf(format string, args ...any) { logf(LevelDebug, "DBG ", format, args...) }
