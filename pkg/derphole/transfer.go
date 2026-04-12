package derphole

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	dharchive "github.com/shayne/derpcat/pkg/derphole/archive"
	"github.com/shayne/derpcat/pkg/derphole/protocol"
	"github.com/shayne/derpcat/pkg/session"
	"github.com/shayne/derpcat/pkg/telemetry"
)

type SendConfig struct {
	Token          string
	Text           string
	What           string
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	ProgressOutput io.Writer
	Emitter        *telemetry.Emitter
	UsePublicDERP  bool
	ForceRelay     bool
}

type ReceiveConfig struct {
	Token          string
	Allocate       bool
	OutputPath     string
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	ProgressOutput io.Writer
	PromptFor      func(io.Reader, io.Writer) (string, error)
	Emitter        *telemetry.Emitter
	UsePublicDERP  bool
	ForceRelay     bool
}

type directorySummary struct {
	FileCount         int   `json:"file_count"`
	UncompressedBytes int64 `json:"uncompressed_bytes"`
}

type sendTransfer struct {
	header        protocol.Header
	body          io.Reader
	cleanup       func() error
	summary       string
	progressTotal int64
}

func Send(ctx context.Context, cfg SendConfig) error {
	tx, err := prepareSendTransfer(cfg)
	if err != nil {
		return err
	}
	if tx.cleanup != nil {
		defer tx.cleanup()
	}

	if cfg.Token == "" {
		listener, err := session.ListenAttach(ctx, session.AttachListenConfig{
			Emitter:       cfg.Emitter,
			UsePublicDERP: cfg.UsePublicDERP,
			ForceRelay:    cfg.ForceRelay,
		})
		if err != nil {
			return err
		}
		defer listener.Close()

		tx.header.Verify = VerificationString(listener.Token)
		WriteSendInstruction(cfg.Stderr, listener.Token)

		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()

		return writeTransfer(conn, tx, cfg.ProgressOutput, cfg.Stderr)
	}

	tx.header.Verify = VerificationString(cfg.Token)
	conn, err := session.DialAttach(ctx, session.AttachDialConfig{
		Token:         cfg.Token,
		Emitter:       cfg.Emitter,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	return writeTransfer(conn, tx, cfg.ProgressOutput, cfg.Stderr)
}

func Receive(ctx context.Context, cfg ReceiveConfig) error {
	stdin := cfg.Stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}

	if cfg.Allocate {
		listener, err := session.ListenAttach(ctx, session.AttachListenConfig{
			Emitter:       cfg.Emitter,
			UsePublicDERP: cfg.UsePublicDERP,
			ForceRelay:    cfg.ForceRelay,
		})
		if err != nil {
			return err
		}
		defer listener.Close()

		WriteReceiveToken(cfg.Stderr, listener.Token)

		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()

		return readTransfer(conn, listener.Token, cfg.Stdout, cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput)
	}

	token := cfg.Token
	if token == "" && cfg.PromptFor != nil {
		var err error
		token, err = cfg.PromptFor(stdin, cfg.Stderr)
		if err != nil {
			return err
		}
	}
	if token == "" {
		return errors.New("receive code is required")
	}

	conn, err := session.DialAttach(ctx, session.AttachDialConfig{
		Token:         token,
		Emitter:       cfg.Emitter,
		UsePublicDERP: cfg.UsePublicDERP,
		ForceRelay:    cfg.ForceRelay,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	return readTransfer(conn, token, cfg.Stdout, cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput)
}

func prepareSendTransfer(cfg SendConfig) (sendTransfer, error) {
	if cfg.Text != "" {
		return sendTransfer{
			header:        protocol.Header{Version: 1, Kind: protocol.KindText},
			body:          strings.NewReader(cfg.Text),
			summary:       fmt.Sprintf("Sending text message (%s)", formatProgressBytes(int64(len(cfg.Text)))),
			progressTotal: -1,
		}, nil
	}
	if cfg.What != "" {
		if info, err := os.Stat(cfg.What); err == nil {
			if info.IsDir() {
				reader, writer := io.Pipe()
				go func() {
					writer.CloseWithError(dharchive.StreamTar(writer, cfg.What))
				}()
				stats, err := dharchive.DescribeTar(cfg.What)
				if err != nil {
					return sendTransfer{}, err
				}
				meta, err := json.Marshal(directorySummary{
					FileCount:         stats.FileCount,
					UncompressedBytes: stats.UncompressedBytes,
				})
				if err != nil {
					return sendTransfer{}, err
				}
				return sendTransfer{
					header: protocol.Header{
						Version:  1,
						Kind:     protocol.KindDirectoryTar,
						Name:     filepath.Base(cfg.What),
						Size:     stats.TarBytes,
						Metadata: meta,
					},
					body:          reader,
					cleanup:       reader.Close,
					summary:       fmt.Sprintf("Sending directory (%s tar) named %q", formatProgressBytes(stats.TarBytes), filepath.Base(cfg.What)),
					progressTotal: stats.TarBytes,
				}, nil
			}
			file, err := os.Open(cfg.What)
			if err != nil {
				return sendTransfer{}, err
			}
			return sendTransfer{
				header: protocol.Header{
					Version: 1,
					Kind:    protocol.KindFile,
					Name:    filepath.Base(cfg.What),
					Size:    info.Size(),
				},
				body:          file,
				cleanup:       file.Close,
				summary:       fmt.Sprintf("Sending %s file named %q", formatProgressBytes(info.Size()), filepath.Base(cfg.What)),
				progressTotal: info.Size(),
			}, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return sendTransfer{}, err
		}
		return sendTransfer{
			header:        protocol.Header{Version: 1, Kind: protocol.KindText},
			body:          strings.NewReader(cfg.What),
			summary:       fmt.Sprintf("Sending text message (%s)", formatProgressBytes(int64(len(cfg.What)))),
			progressTotal: -1,
		}, nil
	}
	if cfg.Stdin != nil {
		return sendTransfer{
			header:        protocol.Header{Version: 1, Kind: protocol.KindText},
			body:          cfg.Stdin,
			progressTotal: -1,
		}, nil
	}
	return sendTransfer{
		header:        protocol.Header{Version: 1, Kind: protocol.KindText},
		body:          strings.NewReader(""),
		summary:       "Sending text message (0B)",
		progressTotal: -1,
	}, nil
}

func writeTransfer(w io.Writer, tx sendTransfer, progressOut, stderr io.Writer) error {
	if tx.summary != "" && stderr != nil {
		fmt.Fprintln(stderr, tx.summary)
	}
	body := tx.body
	progress := NewProgressReporter(progressOut, tx.progressTotal)
	if progress != nil {
		body = progress.Wrap(body)
	}

	if err := protocol.WriteHeader(w, tx.header); err != nil {
		return err
	}
	_, err := io.Copy(w, body)
	if err == nil {
		progress.Finish()
	}
	return err
}

func readTransfer(conn net.Conn, token string, stdout io.Writer, outputPath string, stderr, progressOut io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}

	reader := bufio.NewReader(conn)
	header, err := protocol.ReadHeader(reader)
	if err != nil {
		return err
	}
	if want := VerificationString(token); header.Verify != "" && header.Verify != want {
		return fmt.Errorf("verification mismatch: got %q, want %q", header.Verify, want)
	}

	switch header.Kind {
	case protocol.KindText:
		_, err = io.Copy(stdout, reader)
		return err
	case protocol.KindFile:
		return receiveFile(reader, header, outputPath, stderr, progressOut)
	case protocol.KindDirectoryTar:
		return receiveDirectory(reader, header, outputPath, stderr, progressOut)
	default:
		return fmt.Errorf("unsupported derphole transfer kind %q", header.Kind)
	}
}

func receiveFile(r io.Reader, header protocol.Header, outputPath string, stderr, progressOut io.Writer) error {
	target, err := ResolveOutputPath(outputPath, header.Name)
	if err != nil {
		return err
	}
	if stderr != nil {
		fmt.Fprintf(stderr, "Receiving file (%s) into: %q\n", formatProgressBytes(header.Size), filepath.Base(target))
	}
	if dir := filepath.Dir(target); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer f.Close()

	progress := NewProgressReporter(progressOut, header.Size)
	if progress != nil {
		r = progress.Wrap(r)
	}

	if header.Size > 0 {
		_, err = io.CopyN(f, r, header.Size)
		if err == nil {
			progress.Finish()
		}
		return err
	}
	_, err = io.Copy(f, r)
	return err
}

func receiveDirectory(r io.Reader, header protocol.Header, outputPath string, stderr, progressOut io.Writer) error {
	destRoot, topLevel, err := ResolveDirectoryOutput(outputPath, header.Name)
	if err != nil {
		return err
	}
	if stderr != nil {
		fmt.Fprintf(stderr, "Receiving directory (%s) into: %q/\n", formatProgressBytes(header.Size), topLevel)
		if meta, ok := decodeDirectorySummary(header.Metadata); ok {
			fmt.Fprintf(stderr, "%d files, %s (uncompressed)\n", meta.FileCount, formatProgressBytes(meta.UncompressedBytes))
		}
	}
	progress := NewProgressReporter(progressOut, header.Size)
	if progress != nil {
		r = progress.Wrap(r)
	}
	err = dharchive.ExtractTar(r, destRoot, topLevel)
	if err == nil {
		progress.Finish()
	}
	return err
}

func decodeDirectorySummary(raw []byte) (directorySummary, bool) {
	if len(raw) == 0 {
		return directorySummary{}, false
	}
	var meta directorySummary
	if err := json.Unmarshal(raw, &meta); err != nil {
		return directorySummary{}, false
	}
	return meta, true
}
