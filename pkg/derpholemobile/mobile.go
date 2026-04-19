package derpholemobile

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shayne/derphole/pkg/derphole"
	"github.com/shayne/derphole/pkg/derphole/qrpayload"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
)

var errAmbiguousReceiveOutput = errors.New("received output directory contains more than one file")

var derpholeReceive = derphole.Receive

type Callbacks interface {
	Status(status string)
	Trace(trace string)
	Progress(current int64, total int64)
}

type Receiver struct {
	mu         sync.Mutex
	cancel     context.CancelFunc
	generation uint64
}

func NewReceiver() *Receiver {
	return &Receiver{}
}

func ParsePayload(payload string) (string, error) {
	return qrpayload.ParseReceivePayload(payload)
}

func (r *Receiver) Receive(payloadOrToken string, outputDir string, callbacks Callbacks) (string, error) {
	if strings.TrimSpace(outputDir) == "" {
		return "", errors.New("output directory is required")
	}
	token, err := ParsePayload(payloadOrToken)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}
	transferDir, err := os.MkdirTemp(outputDir, "derphole-receive-*")
	if err != nil {
		return "", err
	}

	ctx, cancel, generation := r.beginContext()
	defer cancel()
	defer r.clearCancel(generation)

	statusWriter := callbackLineWriter{line: func(line string) {
		if callbacks != nil {
			callbacks.Status(line)
		}
	}}
	traceWriter := callbackLineWriter{line: func(line string) {
		if callbacks != nil {
			callbacks.Trace(line)
		}
	}}

	err = derpholeReceive(ctx, derphole.ReceiveConfig{
		Token:          token,
		OutputPath:     transferDir,
		Stderr:         traceWriter,
		ProgressOutput: nil,
		Emitter:        telemetry.New(statusWriter, telemetry.LevelDefault),
		UsePublicDERP:  true,
		ForceRelay:     false,
		ParallelPolicy: session.DefaultParallelPolicy(),
		Progress: func(current, total int64) {
			if callbacks != nil {
				callbacks.Progress(current, total)
			}
		},
	})
	if err != nil {
		_ = os.RemoveAll(transferDir)
		return "", err
	}
	return singleReceivedFile(transferDir)
}

func (r *Receiver) Cancel() {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *Receiver) context() (context.Context, context.CancelFunc) {
	ctx, cancel, _ := r.beginContext()
	return ctx, cancel
}

func (r *Receiver) beginContext() (context.Context, context.CancelFunc, uint64) {
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
	}
	r.generation++
	r.cancel = cancel
	generation := r.generation
	r.mu.Unlock()
	return ctx, cancel, generation
}

func (r *Receiver) clearCancel(generation uint64) {
	r.mu.Lock()
	if r.generation == generation {
		r.cancel = nil
	}
	r.mu.Unlock()
}

type callbackLineWriter struct {
	line func(string)
}

func (w callbackLineWriter) Write(p []byte) (int, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(p)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && w.line != nil {
			w.line(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func singleReceivedFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	if len(files) != 1 {
		if len(files) == 0 {
			return "", io.ErrUnexpectedEOF
		}
		return "", errAmbiguousReceiveOutput
	}
	return files[0], nil
}
