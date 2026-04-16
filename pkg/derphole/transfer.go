package derphole

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	dharchive "github.com/shayne/derphole/pkg/derphole/archive"
	"github.com/shayne/derphole/pkg/derphole/protocol"
	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
	"github.com/shayne/derphole/pkg/derphole/webrtcdirect"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
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
	ParallelPolicy session.ParallelPolicy
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
	ParallelPolicy session.ParallelPolicy
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

const verificationPlaceholder = "0000-0000-0000"

var (
	derpholeSessionDialAttach          = session.DialAttach
	derpholeSessionListen              = session.Listen
	derpholeSessionOffer               = session.Offer
	derpholeSessionReceive             = session.Receive
	derpholeSessionSend                = session.Send
	derpholeWebRelayReceiveWithOptions = webrelay.ReceiveWithOptions
	derpholeNewWebDirect               = func() webrelay.DirectTransport { return webrtcdirect.New() }
)

func normalizeParallelPolicy(policy session.ParallelPolicy) session.ParallelPolicy {
	if policy == (session.ParallelPolicy{}) {
		return session.DefaultParallelPolicy()
	}
	return policy
}

func Send(ctx context.Context, cfg SendConfig) error {
	cfg.ParallelPolicy = normalizeParallelPolicy(cfg.ParallelPolicy)

	tx, err := prepareSendTransfer(cfg)
	if err != nil {
		return err
	}
	if tx.cleanup != nil {
		defer tx.cleanup()
	}

	if cfg.Token == "" {
		return offerTransfer(ctx, cfg, tx)
	}

	tok, err := token.Decode(cfg.Token, time.Now())
	if err != nil {
		return err
	}
	switch {
	case tok.Capabilities&token.CapabilityStdio != 0:
		return sendViaSession(ctx, cfg, tx)
	case tok.Capabilities&token.CapabilityStdioOffer != 0:
		return errors.New("this code expects `derphole receive`, not `derphole send`")
	case tok.Capabilities&token.CapabilityAttach != 0:
		tx.header.Verify = VerificationString(cfg.Token)
		conn, err := derpholeSessionDialAttach(ctx, session.AttachDialConfig{
			Token:          cfg.Token,
			Emitter:        cfg.Emitter,
			UsePublicDERP:  cfg.UsePublicDERP,
			ForceRelay:     cfg.ForceRelay,
			ParallelPolicy: cfg.ParallelPolicy,
		})
		if err != nil {
			return err
		}
		defer conn.Close()
		return writeTransfer(conn, tx, cfg.ProgressOutput, cfg.Stderr)
	default:
		return errors.New("unsupported receive code")
	}
}

func Receive(ctx context.Context, cfg ReceiveConfig) error {
	cfg.ParallelPolicy = normalizeParallelPolicy(cfg.ParallelPolicy)

	stdin := cfg.Stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}

	if cfg.Allocate {
		tokenSink := make(chan string, 1)
		pipeReader, pipeWriter := io.Pipe()
		listenErrCh := make(chan error, 1)
		go func() {
			_, err := derpholeSessionListen(ctx, session.ListenConfig{
				Emitter:       cfg.Emitter,
				TokenSink:     tokenSink,
				StdioOut:      pipeWriter,
				UsePublicDERP: cfg.UsePublicDERP,
				ForceRelay:    cfg.ForceRelay,
			})
			if err != nil {
				_ = pipeWriter.CloseWithError(err)
			}
			listenErrCh <- err
		}()

		var token string
		select {
		case token = <-tokenSink:
		case err := <-listenErrCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}

		WriteReceiveToken(cfg.Stderr, token)
		readErr := readTransfer(pipeReader, token, cfg.Stdout, cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput)
		listenErr := <-listenErrCh
		if readErr != nil {
			return readErr
		}
		return listenErr
	}

	receiveToken := cfg.Token
	if receiveToken == "" && cfg.PromptFor != nil {
		var err error
		receiveToken, err = cfg.PromptFor(stdin, cfg.Stderr)
		if err != nil {
			return err
		}
	}
	if receiveToken == "" {
		return errors.New("receive code is required")
	}

	tok, err := token.Decode(receiveToken, time.Now())
	if err != nil {
		return err
	}
	switch {
	case tok.Capabilities&token.CapabilityStdioOffer != 0:
		pipeReader, pipeWriter := io.Pipe()
		receiveErrCh := make(chan error, 1)
		go func() {
			err := derpholeSessionReceive(ctx, session.ReceiveConfig{
				Token:         receiveToken,
				Emitter:       cfg.Emitter,
				StdioOut:      pipeWriter,
				UsePublicDERP: cfg.UsePublicDERP,
				ForceRelay:    cfg.ForceRelay,
			})
			if err != nil {
				_ = pipeWriter.CloseWithError(err)
			}
			receiveErrCh <- err
		}()
		readErr := readTransfer(pipeReader, receiveToken, cfg.Stdout, cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput)
		receiveErr := <-receiveErrCh
		if readErr != nil {
			return readErr
		}
		return receiveErr
	case tok.Capabilities&token.CapabilityStdio != 0:
		return errors.New("this code expects `derphole send`, not `derphole receive`")
	case tok.Capabilities&token.CapabilityAttach != 0:
		conn, err := derpholeSessionDialAttach(ctx, session.AttachDialConfig{
			Token:          receiveToken,
			Emitter:        cfg.Emitter,
			UsePublicDERP:  cfg.UsePublicDERP,
			ForceRelay:     cfg.ForceRelay,
			ParallelPolicy: cfg.ParallelPolicy,
		})
		if err != nil {
			return err
		}
		defer conn.Close()
		return readTransfer(conn, receiveToken, cfg.Stdout, cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput)
	case tok.Capabilities&token.CapabilityWebFile != 0:
		return receiveViaWebRelay(ctx, cfg, receiveToken)
	default:
		return errors.New("unsupported send code")
	}
}

func receiveViaWebRelay(ctx context.Context, cfg ReceiveConfig, receiveToken string) error {
	sink := newNativeWebFileSink(cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput)
	cb := webrelay.Callbacks{
		Status: func(status string) {
			if cfg.Emitter != nil {
				cfg.Emitter.Debug(status)
			}
		},
		Progress: func(webrelay.Progress) {},
		Trace: func(trace string) {
			if cfg.Emitter != nil {
				cfg.Emitter.Debug("webrelay-" + trace)
			}
		},
	}
	opts := webrelay.TransferOptions{}
	if !cfg.ForceRelay && derpholeNewWebDirect != nil {
		opts.Direct = derpholeNewWebDirect()
	}
	return derpholeWebRelayReceiveWithOptions(ctx, receiveToken, sink, cb, opts)
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

func transferSessionExpectedBytes(tx sendTransfer) int64 {
	if tx.progressTotal < 0 {
		return -1
	}
	header := tx.header
	if header.Verify == "" {
		header.Verify = verificationPlaceholder
	}
	headerBytes, err := protocol.HeaderWireSize(header)
	if err != nil {
		return -1
	}
	return headerBytes + tx.progressTotal
}

func writeTransferWithProgress(w io.Writer, tx sendTransfer, progressOut, stderr io.Writer) (*ProgressReporter, error) {
	if tx.summary != "" && stderr != nil {
		fmt.Fprintln(stderr, tx.summary)
	}
	body := tx.body
	progress := NewProgressReporter(progressOut, tx.progressTotal)
	if progress != nil {
		body = progress.Wrap(body)
	}

	if err := protocol.WriteHeader(w, tx.header); err != nil {
		return progress, err
	}
	_, err := io.Copy(w, body)
	return progress, err
}

func finishTransferProgress(progress *ProgressReporter, err error) {
	if err == nil {
		progress.Finish()
		return
	}
	progress.Abort()
}

func writeTransfer(w io.Writer, tx sendTransfer, progressOut, stderr io.Writer) error {
	progress, err := writeTransferWithProgress(w, tx, progressOut, stderr)
	finishTransferProgress(progress, err)
	return err
}

func offerTransfer(ctx context.Context, cfg SendConfig, tx sendTransfer) error {
	pipeReader, pipeWriter := io.Pipe()
	tokenSink := make(chan string, 1)
	offerErrCh := make(chan error, 1)
	go func() {
		_, err := derpholeSessionOffer(ctx, session.OfferConfig{
			Emitter:            cfg.Emitter,
			TokenSink:          tokenSink,
			StdioIn:            pipeReader,
			StdioExpectedBytes: transferSessionExpectedBytes(tx),
			UsePublicDERP:      cfg.UsePublicDERP,
			ForceRelay:         cfg.ForceRelay,
			ParallelPolicy:     cfg.ParallelPolicy,
		})
		offerErrCh <- err
	}()

	var token string
	select {
	case token = <-tokenSink:
	case err := <-offerErrCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}

	tx.header.Verify = VerificationString(token)
	WriteSendInstruction(cfg.Stderr, token)

	progress, writeErr := writeTransferWithProgress(pipeWriter, tx, cfg.ProgressOutput, cfg.Stderr)
	_ = pipeWriter.CloseWithError(writeErr)
	offerErr := <-offerErrCh
	err := preferSessionPipeError(writeErr, offerErr)
	finishTransferProgress(progress, err)
	return err
}

func sendViaSession(ctx context.Context, cfg SendConfig, tx sendTransfer) error {
	pipeReader, pipeWriter := io.Pipe()
	sendErrCh := make(chan error, 1)
	tx.header.Verify = VerificationString(cfg.Token)
	go func() {
		sendErrCh <- derpholeSessionSend(ctx, session.SendConfig{
			Token:              cfg.Token,
			Emitter:            cfg.Emitter,
			StdioIn:            pipeReader,
			StdioExpectedBytes: transferSessionExpectedBytes(tx),
			UsePublicDERP:      cfg.UsePublicDERP,
			ForceRelay:         cfg.ForceRelay,
			ParallelPolicy:     cfg.ParallelPolicy,
		})
	}()

	progress, writeErr := writeTransferWithProgress(pipeWriter, tx, cfg.ProgressOutput, cfg.Stderr)
	_ = pipeWriter.CloseWithError(writeErr)
	sendErr := <-sendErrCh
	err := preferSessionPipeError(writeErr, sendErr)
	finishTransferProgress(progress, err)
	return err
}

func readTransfer(r io.Reader, token string, stdout io.Writer, outputPath string, stderr, progressOut io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}

	reader := bufio.NewReader(r)
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
		var copied int64
		copied, err = io.CopyN(f, r, header.Size)
		if err == nil {
			progress.Finish()
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("incomplete file transfer: received %s of %s: %w", formatProgressBytes(copied), formatProgressBytes(header.Size), err)
		}
		return err
	}
	_, err = io.Copy(f, r)
	return err
}

type nativeWebFileSink struct {
	outputPath  string
	stderr      io.Writer
	progressOut io.Writer
	progress    *ProgressReporter
	file        *os.File
}

func newNativeWebFileSink(outputPath string, stderr, progressOut io.Writer) *nativeWebFileSink {
	return &nativeWebFileSink{
		outputPath:  outputPath,
		stderr:      stderr,
		progressOut: progressOut,
	}
}

func (s *nativeWebFileSink) Open(_ context.Context, meta webproto.Meta) error {
	target, err := ResolveOutputPath(s.outputPath, meta.Name)
	if err != nil {
		return err
	}
	if s.stderr != nil {
		fmt.Fprintf(s.stderr, "Receiving file (%s) into: %q\n", formatProgressBytes(meta.Size), filepath.Base(target))
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
	s.file = f
	s.progress = NewProgressReporter(s.progressOut, meta.Size)
	return nil
}

func (s *nativeWebFileSink) WriteChunk(_ context.Context, chunk []byte) error {
	if s.file == nil {
		return errors.New("file sink is not open")
	}
	n, err := s.file.Write(chunk)
	if n > 0 {
		s.progress.Add(n)
	}
	if err != nil {
		return err
	}
	if n != len(chunk) {
		return io.ErrShortWrite
	}
	return nil
}

func (s *nativeWebFileSink) Close(_ context.Context) error {
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	if err != nil {
		s.progress.Abort()
		return err
	}
	s.progress.Finish()
	return nil
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

func preferSessionPipeError(pipeErr, sessionErr error) error {
	if sessionErr == nil {
		return pipeErr
	}
	if pipeErr == nil {
		return sessionErr
	}
	if errors.Is(pipeErr, io.ErrClosedPipe) {
		return sessionErr
	}
	return pipeErr
}
