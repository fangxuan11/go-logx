package logx

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultDir      = "/var/log/"
	DefaultMaxBytes = int64(50 * 1024 * 1024)
)

type contextKey string

const metaKey contextKey = "logx_meta"

var executorSeq atomic.Uint64

type Meta struct {
	LogID    string
	Executor string
}

type Logger struct {
	writer *rotatingWriter
}

func New(dir string, maxBytes int64) (*Logger, error) {
	if dir == "" {
		dir = DefaultDir
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	writer, err := newRotatingWriter(dir, maxBytes)
	if err != nil {
		return nil, err
	}
	return &Logger{writer: writer}, nil
}

func (l *Logger) Close() error {
	if l == nil || l.writer == nil {
		return nil
	}
	return l.writer.Close()
}

func (l *Logger) Info(ctx context.Context, format string, args ...any) {
	l.write(ctx, "INFO", format, args...)
}

func (l *Logger) Error(ctx context.Context, format string, args ...any) {
	l.write(ctx, "ERROR", format, args...)
}

func (l *Logger) write(ctx context.Context, level string, format string, args ...any) {
	if l == nil || l.writer == nil {
		return
	}
	meta := MetaFromContext(ctx)
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] [%s] [%s][%s] [%s] %s\n", formatTime(time.Now()), level, meta.Executor, meta.LogID, callerLocation(), message)
	_, _ = l.writer.Write([]byte(line))
}

func NewRequestMeta(requestID string) Meta {
	return Meta{
		LogID:    NewLogID(requestID),
		Executor: fmt.Sprintf("http-nio-80-exec-%d", executorSeq.Add(1)),
	}
}

func WithMeta(ctx context.Context, meta Meta) context.Context {
	return context.WithValue(ctx, metaKey, meta)
}

func MetaFromContext(ctx context.Context) Meta {
	if ctx != nil {
		if meta, ok := ctx.Value(metaKey).(Meta); ok && meta.LogID != "" && meta.Executor != "" {
			return meta
		}
	}
	return NewRequestMeta("")
}

func NewLogID(requestID string) string {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return randomHex(32)
	}
	prefixLen := 32 - len(requestID)
	if prefixLen < 0 {
		prefixLen = 0
	}
	return randomHex(prefixLen) + "-" + requestID
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05.000")
}

func randomHex(length int) string {
	if length <= 0 {
		return ""
	}
	bytes := make([]byte, (length+1)/2)
	if _, err := rand.Read(bytes); err != nil {
		now := time.Now().UnixNano()
		return fmt.Sprintf("%032x", now)[:length]
	}
	return hex.EncodeToString(bytes)[:length]
}

func callerLocation() string {
	for skip := 2; skip <= 12; skip++ {
		pc, file, line, ok := runtime.Caller(skip)
		if !ok {
			continue
		}
		fn := runtime.FuncForPC(pc)
		fnName := ""
		if fn != nil {
			fnName = fn.Name()
		}
		if strings.HasSuffix(file, "internal/logx/logger.go") ||
			strings.HasSuffix(fnName, ".logInfo") ||
			strings.HasSuffix(fnName, ".logError") ||
			strings.HasSuffix(fnName, ".Info") ||
			strings.HasSuffix(fnName, ".Error") {
			continue
		}
		return fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}
	return "unknown:0"
}

func JSONForLog(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf(`{"marshal_error":%q}`, err.Error())
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return string(data)
	}
	redactSensitiveJSON(decoded)
	redacted, err := json.Marshal(decoded)
	if err != nil {
		return string(data)
	}
	return string(redacted)
}

func redactSensitiveJSON(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isSensitiveKey(key) {
				typed[key] = "***"
				continue
			}
			redactSensitiveJSON(child)
		}
	case []any:
		for _, child := range typed {
			redactSensitiveJSON(child)
		}
	}
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	if strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "authorization") {
		return true
	}
	return false
}

type rotatingWriter struct {
	dir      string
	maxBytes int64

	mu          sync.Mutex
	file        *os.File
	currentDay  string
	currentSize int64
	rotateSeq   int64
}

func newRotatingWriter(dir string, maxBytes int64) (*rotatingWriter, error) {
	writer := &rotatingWriter{dir: dir, maxBytes: maxBytes}
	if err := writer.openForDay(time.Now()); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureReadyLocked(len(p)); err != nil {
		return 0, err
	}
	n, err := w.file.Write(p)
	w.currentSize += int64(n)
	return n, err
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *rotatingWriter) ensureReadyLocked(nextBytes int) error {
	now := time.Now()
	day := now.Format("2006-01-02")
	if w.file == nil || w.currentDay != day {
		if w.file != nil {
			_ = w.file.Close()
			w.file = nil
		}
		return w.openForDay(now)
	}
	if w.currentSize > 0 && w.currentSize+int64(nextBytes) > w.maxBytes {
		if err := w.rotateLocked(now); err != nil {
			return err
		}
	}
	return nil
}

func (w *rotatingWriter) openForDay(t time.Time) error {
	day := t.Format("2006-01-02")
	dayDir := filepath.Join(w.dir, day)
	if err := os.MkdirAll(dayDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dayDir, "app.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	w.file = file
	w.currentDay = day
	w.currentSize = info.Size()
	return nil
}

func (w *rotatingWriter) rotateLocked(t time.Time) error {
	if w.file == nil {
		return w.openForDay(t)
	}
	logPath := w.file.Name()
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil

	info, err := os.Stat(logPath)
	if err != nil {
		return err
	}
	if info.Size() > 0 {
		w.rotateSeq++
		zipPath := filepath.Join(filepath.Dir(logPath), fmt.Sprintf("app-%s-%03d.log.zip", t.Format("20060102150405"), w.rotateSeq))
		if err := zipFile(logPath, zipPath); err != nil {
			return err
		}
		if err := os.Remove(logPath); err != nil {
			return err
		}
	}
	return w.openForDay(t)
}

func zipFile(source string, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer out.Close()

	zipWriter := zip.NewWriter(out)
	defer zipWriter.Close()

	entry, err := zipWriter.Create(filepath.Base(source))
	if err != nil {
		return err
	}
	_, err = io.Copy(entry, in)
	return err
}
