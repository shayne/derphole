// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphole

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	dharchive "github.com/shayne/derphole/pkg/derphole/archive"
	"github.com/shayne/derphole/pkg/derphole/protocol"
	"github.com/shayne/derphole/pkg/derphole/webproto"
	"github.com/shayne/derphole/pkg/derphole/webrelay"
	"github.com/shayne/derphole/pkg/derphole/webrtcdirect"
	"github.com/shayne/derphole/pkg/session"
	"github.com/shayne/derphole/pkg/telemetry"
	"github.com/shayne/derphole/pkg/token"
	"github.com/shayne/derphole/pkg/transfertrace"
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
	QR             bool
	ParallelPolicy session.ParallelPolicy
	Trace          *transfertrace.Recorder
	DirectTCPPort  int
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
	Progress       func(current, total int64)
	Trace          *transfertrace.Recorder
	DirectTCPPort  int
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
	blockPayload  io.ReaderAt
	blockSize     int64
}

const verificationPlaceholder = "0000-0000-0000"
const unknownSessionProgressHeaderBytes int64 = 1<<63 - 1

var (
	derpholeSessionDialAttach          = session.DialAttach
	derpholeSessionListen              = session.Listen
	derpholeSessionOffer               = session.Offer
	derpholeSessionReceive             = session.Receive
	derpholeSessionSend                = session.Send
	derpholeWebRelayReceiveWithOptions = webrelay.ReceiveWithOptions
	derpholeNewWebDirect               = func() webrelay.DirectTransport { return webrtcdirect.New() }
)

var errBlockTransferHandled = errors.New("block transfer handled")

func normalizeParallelPolicy(policy session.ParallelPolicy) session.ParallelPolicy {
	if policy == (session.ParallelPolicy{}) {
		return session.DefaultParallelPolicy()
	}
	return policy
}

func Send(ctx context.Context, cfg SendConfig) error {
	if err := validateDirectTCPPort(cfg.DirectTCPPort); err != nil {
		return err
	}
	cfg.ParallelPolicy = normalizeParallelPolicy(cfg.ParallelPolicy)
	if err := validateQRSendConfig(cfg); err != nil {
		return err
	}
	tx, err := prepareSendTransfer(cfg)
	if err != nil {
		return err
	}
	if tx.cleanup != nil {
		defer func() { _ = tx.cleanup() }()
	}

	if cfg.Token == "" {
		return offerTransfer(ctx, cfg, tx)
	}
	return sendWithReceiveToken(ctx, cfg, tx)
}

func sendWithReceiveToken(ctx context.Context, cfg SendConfig, tx sendTransfer) error {
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
		return sendViaAttach(ctx, cfg, tx)
	default:
		return errors.New("unsupported receive code")
	}
}

func sendViaAttach(ctx context.Context, cfg SendConfig, tx sendTransfer) error {
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
	defer func() { _ = conn.Close() }()
	return writeTransfer(conn, tx, cfg.ProgressOutput, cfg.Stderr)
}

func validateQRSendConfig(cfg SendConfig) error {
	if !cfg.QR {
		return nil
	}
	const qrFileOnlyErr = "--qr only supports file sends"
	if cfg.Text != "" || cfg.What == "" {
		return errors.New(qrFileOnlyErr)
	}
	info, err := os.Stat(cfg.What)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New(qrFileOnlyErr)
		}
		return err
	}
	if info.IsDir() {
		return errors.New(qrFileOnlyErr)
	}
	return nil
}

func Receive(ctx context.Context, cfg ReceiveConfig) error {
	if err := validateDirectTCPPort(cfg.DirectTCPPort); err != nil {
		return err
	}
	cfg.ParallelPolicy = normalizeParallelPolicy(cfg.ParallelPolicy)
	if cfg.Allocate {
		return receiveAllocated(ctx, cfg)
	}
	receiveToken, err := resolveReceiveToken(cfg, receivePromptInput(cfg.Stdin))
	if err != nil {
		return err
	}
	return receiveWithToken(ctx, cfg, receiveToken)
}

func validateDirectTCPPort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("direct TCP port %d must be zero or within [1,65535]", port)
	}
	return nil
}

func receivePromptInput(r io.Reader) io.Reader {
	if r != nil {
		return r
	}
	return strings.NewReader("")
}

func receiveAllocated(ctx context.Context, cfg ReceiveConfig) error {
	tokenSink := make(chan string, 1)
	pipeReader, pipeWriter := io.Pipe()
	var receiveToken atomic.Value
	blockReceiver := session.BlockReceiver(nil)
	if cfg.UsePublicDERP {
		blockReceiver = newSessionBlockReceiver(cfg, func() string {
			token, _ := receiveToken.Load().(string)
			return token
		}, func() {
			_ = pipeWriter.CloseWithError(errBlockTransferHandled)
		})
	}
	listenErrCh := make(chan error, 1)
	go func() {
		_, err := derpholeSessionListen(ctx, session.ListenConfig{
			Emitter:       cfg.Emitter,
			TokenSink:     tokenSink,
			StdioOut:      pipeWriter,
			BlockReceiver: blockReceiver,
			UsePublicDERP: cfg.UsePublicDERP,
			ForceRelay:    cfg.ForceRelay,
			Trace:         cfg.Trace,
			DirectTCPPort: cfg.DirectTCPPort,
		})
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
		}
		listenErrCh <- err
	}()

	token, err := waitForAllocatedToken(ctx, tokenSink, listenErrCh)
	if err != nil {
		return err
	}
	receiveToken.Store(token)
	WriteReceiveToken(cfg.Stderr, token)
	readErr := readTransfer(pipeReader, token, cfg.Stdout, cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput, cfg.Progress)
	listenErr := <-listenErrCh
	return preferSessionPipeError(readErr, listenErr)
}

func waitForAllocatedToken(ctx context.Context, tokenSink <-chan string, listenErrCh <-chan error) (string, error) {
	select {
	case token := <-tokenSink:
		return token, nil
	case err := <-listenErrCh:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func resolveReceiveToken(cfg ReceiveConfig, stdin io.Reader) (string, error) {
	receiveToken := cfg.Token
	if receiveToken == "" && cfg.PromptFor != nil {
		var err error
		receiveToken, err = cfg.PromptFor(stdin, cfg.Stderr)
		if err != nil {
			return "", err
		}
	}
	if receiveToken == "" {
		return "", errors.New("receive code is required")
	}
	return receiveToken, nil
}

func receiveWithToken(ctx context.Context, cfg ReceiveConfig, receiveToken string) error {
	tok, err := token.Decode(receiveToken, time.Now())
	if err != nil {
		return err
	}
	switch {
	case tok.Capabilities&token.CapabilityStdioOffer != 0:
		return receiveViaStdioOffer(ctx, cfg, receiveToken)
	case tok.Capabilities&token.CapabilityStdio != 0:
		return errors.New("this code expects `derphole send`, not `derphole receive`")
	case tok.Capabilities&token.CapabilityAttach != 0:
		return receiveViaAttach(ctx, cfg, receiveToken)
	case tok.Capabilities&token.CapabilityWebFile != 0:
		return receiveViaWebRelay(ctx, cfg, receiveToken)
	default:
		return errors.New("unsupported send code")
	}
}

func receiveViaStdioOffer(ctx context.Context, cfg ReceiveConfig, receiveToken string) error {
	pipeReader, pipeWriter := io.Pipe()
	blockReceiver := session.BlockReceiver(nil)
	if cfg.UsePublicDERP {
		blockReceiver = newSessionBlockReceiver(cfg, func() string {
			return receiveToken
		}, func() {
			_ = pipeWriter.CloseWithError(errBlockTransferHandled)
		})
	}
	receiveErrCh := make(chan error, 1)
	go func() {
		err := derpholeSessionReceive(ctx, session.ReceiveConfig{
			Token:         receiveToken,
			Emitter:       cfg.Emitter,
			StdioOut:      pipeWriter,
			BlockReceiver: blockReceiver,
			UsePublicDERP: cfg.UsePublicDERP,
			ForceRelay:    cfg.ForceRelay,
			Trace:         cfg.Trace,
			DirectTCPPort: cfg.DirectTCPPort,
		})
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
		}
		receiveErrCh <- err
	}()
	readErr := readTransfer(pipeReader, receiveToken, cfg.Stdout, cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput, cfg.Progress)
	receiveErr := <-receiveErrCh
	return preferSessionPipeError(readErr, receiveErr)
}

func receiveViaAttach(ctx context.Context, cfg ReceiveConfig, receiveToken string) error {
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
	defer func() { _ = conn.Close() }()
	return readTransfer(conn, receiveToken, cfg.Stdout, cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput, cfg.Progress)
}

func receiveViaWebRelay(ctx context.Context, cfg ReceiveConfig, receiveToken string) error {
	sink := newNativeWebFileSink(cfg.OutputPath, cfg.Stderr, cfg.ProgressOutput, cfg.Progress)
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

func newSessionBlockReceiver(cfg ReceiveConfig, token func() string, handled func()) session.BlockReceiver {
	return func(ctx context.Context, req session.BlockReceiveRequest) (session.BlockReceiveSink, error) {
		header, err := protocol.ReadHeader(bufio.NewReader(bytes.NewReader(req.Header)))
		if err != nil {
			return nil, err
		}
		if want := VerificationString(token()); header.Verify != "" && header.Verify != want {
			return nil, fmt.Errorf("verification mismatch: got %q, want %q", header.Verify, want)
		}
		if header.Kind != protocol.KindFile {
			return nil, fmt.Errorf("unsupported block transfer kind %q", header.Kind)
		}
		if header.Size != req.PayloadSize {
			return nil, fmt.Errorf("block payload size mismatch: got %d, want header size %d", req.PayloadSize, header.Size)
		}
		target, err := prepareReceiveFileTarget(cfg.OutputPath, header, cfg.Stderr)
		if err != nil {
			return nil, err
		}
		f, err := os.Create(target)
		if err != nil {
			return nil, err
		}
		progress := NewProgressReporterWithCallback(cfg.ProgressOutput, header.Size, cfg.Progress)
		if header.Size == 0 {
			progress.Finish()
		}
		if handled != nil {
			handled()
		}
		return &receiveBlockFileSink{
			file:     f,
			progress: progress,
			size:     header.Size,
		}, nil
	}
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
				blockPayload:  file,
				blockSize:     info.Size(),
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

func sessionBlockSourceForTransfer(tx sendTransfer) (*session.BlockSource, int64, error) {
	if tx.header.Kind != protocol.KindFile || tx.blockPayload == nil || tx.blockSize < 0 {
		return nil, 0, nil
	}
	blockSource := &session.BlockSource{
		Payload:     tx.blockPayload,
		PayloadSize: tx.blockSize,
	}
	headerBytes, err := configureSessionBlockSource(blockSource, tx)
	return blockSource, headerBytes, err
}

func transferHeaderBytes(tx sendTransfer) ([]byte, error) {
	var header bytes.Buffer
	if err := protocol.WriteHeader(&header, tx.header); err != nil {
		return nil, err
	}
	return append([]byte(nil), header.Bytes()...), nil
}

func configureSessionBlockSource(blockSource *session.BlockSource, tx sendTransfer) (int64, error) {
	if blockSource == nil {
		return 0, errors.New("nil block source")
	}
	headerBytes, err := transferHeaderBytes(tx)
	if err != nil {
		return 0, err
	}
	blockSource.Header = headerBytes
	blockSource.OpenStream = func() (io.ReadCloser, error) {
		return nopReadCloser{Reader: io.MultiReader(bytes.NewReader(headerBytes), io.NewSectionReader(tx.blockPayload, 0, tx.blockSize))}, nil
	}
	return int64(len(headerBytes)), nil
}

type nopReadCloser struct {
	io.Reader
}

func (nopReadCloser) Close() error {
	return nil
}

func writeTransferWithProgress(w io.Writer, tx sendTransfer, progressOut, stderr io.Writer) (*ProgressReporter, error) {
	progress := NewProgressReporter(progressOut, tx.progressTotal)
	err := writeTransferWithReporter(w, tx, progress, stderr)
	return progress, err
}

func writeTransferWithReporter(w io.Writer, tx sendTransfer, progress *ProgressReporter, stderr io.Writer) error {
	if tx.summary != "" && stderr != nil {
		_, _ = fmt.Fprintln(stderr, tx.summary)
	}
	body := tx.body
	if progress != nil {
		body = progress.Wrap(body)
	}

	if err := protocol.WriteHeader(w, tx.header); err != nil {
		return err
	}
	_, err := io.Copy(w, body)
	return err
}

func writeTransferWithoutProgress(w io.Writer, tx sendTransfer, stderr io.Writer) error {
	if tx.summary != "" && stderr != nil {
		_, _ = fmt.Fprintln(stderr, tx.summary)
	}
	if err := protocol.WriteHeader(w, tx.header); err != nil {
		return err
	}
	_, err := io.Copy(w, tx.body)
	return err
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

func closePipeReaderOnContext(ctx context.Context, r *io.PipeReader) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = r.CloseWithError(ctx.Err())
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}

func senderPeerPayloadProgress(progress *ProgressReporter, headerBytes, total int64) func(sessionBytes int64, transferElapsedMS int64) {
	if progress == nil || total < 0 {
		return nil
	}
	return func(sessionBytes int64, transferElapsedMS int64) {
		setSenderPeerPayloadProgress(progress, headerBytes, total, sessionBytes, transferElapsedMS)
	}
}

func setSenderPeerPayloadProgress(progress *ProgressReporter, headerBytes, total, sessionBytes, transferElapsedMS int64) {
	payloadBytes := sessionBytes - headerBytes
	if payloadBytes < 0 {
		payloadBytes = 0
	}
	if payloadBytes > total {
		payloadBytes = total
	}
	progress.SetWithElapsed(payloadBytes, time.Duration(transferElapsedMS)*time.Millisecond)
}

func offerTransfer(ctx context.Context, cfg SendConfig, tx sendTransfer) error {
	if handled, err := offerTransferBlockIfSupported(ctx, cfg, tx); handled {
		return err
	}
	return offerTransferStream(ctx, cfg, tx)
}

func offerTransferBlockIfSupported(ctx context.Context, cfg SendConfig, tx sendTransfer) (bool, error) {
	if !cfg.UsePublicDERP {
		return false, nil
	}
	return offerTransferBlock(ctx, cfg, tx)
}

func offerTransferStream(ctx context.Context, cfg SendConfig, tx sendTransfer) error {
	pipeReader, pipeWriter := io.Pipe()
	stopPipeCancel := closePipeReaderOnContext(ctx, pipeReader)
	defer stopPipeCancel()
	tokenSink := make(chan string, 1)
	offerErrCh := make(chan error, 1)
	progress := NewProgressReporter(cfg.ProgressOutput, tx.progressTotal)
	var headerBytes atomic.Int64
	headerBytes.Store(unknownSessionProgressHeaderBytes)
	var progressCallback func(int64, int64)
	if cfg.UsePublicDERP {
		progressCallback = func(sessionBytes int64, transferElapsedMS int64) {
			if progress == nil || tx.progressTotal < 0 {
				return
			}
			setSenderPeerPayloadProgress(progress, headerBytes.Load(), tx.progressTotal, sessionBytes, transferElapsedMS)
		}
	}
	go func() {
		_, err := derpholeSessionOffer(ctx, session.OfferConfig{
			Emitter:            cfg.Emitter,
			TokenSink:          tokenSink,
			StdioIn:            pipeReader,
			StdioExpectedBytes: transferSessionExpectedBytes(tx),
			Progress:           progressCallback,
			UsePublicDERP:      cfg.UsePublicDERP,
			ForceRelay:         cfg.ForceRelay,
			ParallelPolicy:     cfg.ParallelPolicy,
			Trace:              cfg.Trace,
			DirectTCPPort:      cfg.DirectTCPPort,
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
	realHeaderBytes, err := protocol.HeaderWireSize(tx.header)
	if err != nil {
		_ = pipeWriter.CloseWithError(err)
		offerErr := <-offerErrCh
		err = preferSessionPipeError(err, offerErr)
		finishTransferProgress(progress, err)
		return err
	}
	headerBytes.Store(realHeaderBytes)
	if cfg.QR {
		WriteSendQRInstruction(cfg.Stderr, token)
	} else {
		WriteSendInstruction(cfg.Stderr, token)
	}

	var writeErr error
	if cfg.UsePublicDERP {
		writeErr = writeTransferWithoutProgress(pipeWriter, tx, cfg.Stderr)
	} else {
		writeErr = writeTransferWithReporter(pipeWriter, tx, progress, cfg.Stderr)
	}
	_ = pipeWriter.CloseWithError(writeErr)
	offerErr := <-offerErrCh
	err = preferSessionPipeError(writeErr, offerErr)
	finishTransferProgress(progress, err)
	return err
}

func offerTransferBlock(ctx context.Context, cfg SendConfig, tx sendTransfer) (bool, error) {
	if !sendTransferSupportsBlock(tx) {
		return false, nil
	}
	tokenSink := make(chan string, 1)
	offerErrCh := make(chan error, 1)
	progress := NewProgressReporter(cfg.ProgressOutput, tx.progressTotal)
	var headerBytes atomic.Int64
	headerBytes.Store(unknownSessionProgressHeaderBytes)
	var blockHeader atomic.Value
	blockSource := newOfferSessionBlockSource(tx, &blockHeader)
	progressCallback := func(sessionBytes int64, transferElapsedMS int64) {
		if progress == nil || tx.progressTotal < 0 {
			return
		}
		setSenderPeerPayloadProgress(progress, headerBytes.Load(), tx.progressTotal, sessionBytes, transferElapsedMS)
	}
	go func() {
		_, err := derpholeSessionOffer(ctx, session.OfferConfig{
			Emitter:            cfg.Emitter,
			TokenSink:          tokenSink,
			BlockSource:        blockSource,
			StdioExpectedBytes: transferSessionExpectedBytes(tx),
			Progress:           progressCallback,
			UsePublicDERP:      cfg.UsePublicDERP,
			ForceRelay:         cfg.ForceRelay,
			ParallelPolicy:     cfg.ParallelPolicy,
			Trace:              cfg.Trace,
			DirectTCPPort:      cfg.DirectTCPPort,
		})
		offerErrCh <- err
	}()

	token, err := waitForOfferBlockToken(ctx, tokenSink, offerErrCh)
	if err != nil {
		finishTransferProgress(progress, err)
		return true, err
	}
	header, err := offerBlockHeaderForToken(tx, token)
	if err != nil {
		return finishOfferBlockSetupError(progress, offerErrCh, err)
	}
	blockHeader.Store(header)
	headerBytes.Store(int64(len(header)))
	writeSendOfferInstruction(cfg, tx.summary, token)

	offerErr := <-offerErrCh
	finishTransferProgress(progress, offerErr)
	return true, offerErr
}

func sendTransferSupportsBlock(tx sendTransfer) bool {
	return tx.header.Kind == protocol.KindFile && tx.blockPayload != nil && tx.blockSize >= 0
}

func newOfferSessionBlockSource(tx sendTransfer, headerValue *atomic.Value) *session.BlockSource {
	return &session.BlockSource{
		Payload:     tx.blockPayload,
		PayloadSize: tx.blockSize,
		HeaderFunc: func() []byte {
			header, _ := headerValue.Load().([]byte)
			return header
		},
		OpenStream: func() (io.ReadCloser, error) {
			header, _ := headerValue.Load().([]byte)
			if len(header) == 0 {
				return nil, errors.New("block transfer header is not ready")
			}
			return nopReadCloser{Reader: io.MultiReader(bytes.NewReader(header), io.NewSectionReader(tx.blockPayload, 0, tx.blockSize))}, nil
		},
	}
}

func waitForOfferBlockToken(ctx context.Context, tokenSink <-chan string, offerErrCh <-chan error) (string, error) {
	select {
	case token := <-tokenSink:
		return token, nil
	case err := <-offerErrCh:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func offerBlockHeaderForToken(tx sendTransfer, token string) ([]byte, error) {
	tx.header.Verify = VerificationString(token)
	return transferHeaderBytes(tx)
}

func finishOfferBlockSetupError(progress *ProgressReporter, offerErrCh <-chan error, err error) (bool, error) {
	offerErr := <-offerErrCh
	err = preferSessionPipeError(err, offerErr)
	finishTransferProgress(progress, err)
	return true, err
}

func writeSendOfferInstruction(cfg SendConfig, summary string, token string) {
	if summary != "" && cfg.Stderr != nil {
		_, _ = fmt.Fprintln(cfg.Stderr, summary)
	}
	if cfg.QR {
		WriteSendQRInstruction(cfg.Stderr, token)
		return
	}
	WriteSendInstruction(cfg.Stderr, token)
}

func sendViaSession(ctx context.Context, cfg SendConfig, tx sendTransfer) error {
	if cfg.UsePublicDERP {
		handled, err := sendViaSessionBlock(ctx, cfg, tx)
		if handled {
			return err
		}
	}
	pipeReader, pipeWriter := io.Pipe()
	stopPipeCancel := closePipeReaderOnContext(ctx, pipeReader)
	defer stopPipeCancel()
	sendErrCh := make(chan error, 1)
	tx.header.Verify = VerificationString(cfg.Token)
	headerBytes, err := protocol.HeaderWireSize(tx.header)
	if err != nil {
		return err
	}
	progress := NewProgressReporter(cfg.ProgressOutput, tx.progressTotal)
	go func() {
		var progressCallback func(int64, int64)
		if cfg.UsePublicDERP {
			progressCallback = senderPeerPayloadProgress(progress, headerBytes, tx.progressTotal)
		}
		sendErrCh <- derpholeSessionSend(ctx, session.SendConfig{
			Token:              cfg.Token,
			Emitter:            cfg.Emitter,
			StdioIn:            pipeReader,
			StdioExpectedBytes: transferSessionExpectedBytes(tx),
			Progress:           progressCallback,
			UsePublicDERP:      cfg.UsePublicDERP,
			ForceRelay:         cfg.ForceRelay,
			ParallelPolicy:     cfg.ParallelPolicy,
			Trace:              cfg.Trace,
		})
	}()

	var writeErr error
	if cfg.UsePublicDERP {
		writeErr = writeTransferWithoutProgress(pipeWriter, tx, cfg.Stderr)
	} else {
		writeErr = writeTransferWithReporter(pipeWriter, tx, progress, cfg.Stderr)
	}
	_ = pipeWriter.CloseWithError(writeErr)
	sendErr := <-sendErrCh
	err = preferSessionPipeError(writeErr, sendErr)
	finishTransferProgress(progress, err)
	return err
}

func sendViaSessionBlock(ctx context.Context, cfg SendConfig, tx sendTransfer) (bool, error) {
	tx.header.Verify = VerificationString(cfg.Token)
	blockSource, headerBytes, err := sessionBlockSourceForTransfer(tx)
	if err != nil {
		return true, err
	}
	if blockSource == nil {
		return false, nil
	}
	if tx.summary != "" && cfg.Stderr != nil {
		_, _ = fmt.Fprintln(cfg.Stderr, tx.summary)
	}
	progress := NewProgressReporter(cfg.ProgressOutput, tx.progressTotal)
	err = derpholeSessionSend(ctx, session.SendConfig{
		Token:              cfg.Token,
		Emitter:            cfg.Emitter,
		BlockSource:        blockSource,
		StdioExpectedBytes: headerBytes + tx.progressTotal,
		Progress:           senderPeerPayloadProgress(progress, headerBytes, tx.progressTotal),
		UsePublicDERP:      cfg.UsePublicDERP,
		ForceRelay:         cfg.ForceRelay,
		ParallelPolicy:     cfg.ParallelPolicy,
		Trace:              cfg.Trace,
		DirectTCPPort:      cfg.DirectTCPPort,
	})
	finishTransferProgress(progress, err)
	return true, err
}

func readTransfer(r io.Reader, token string, stdout io.Writer, outputPath string, stderr, progressOut io.Writer, progress func(current, total int64)) error {
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
		return receiveFile(reader, header, outputPath, stderr, progressOut, progress)
	case protocol.KindDirectoryTar:
		return receiveDirectory(reader, header, outputPath, stderr, progressOut, progress)
	default:
		return fmt.Errorf("unsupported derphole transfer kind %q", header.Kind)
	}
}

func receiveFile(r io.Reader, header protocol.Header, outputPath string, stderr, progressOut io.Writer, progressCallback func(current, total int64)) error {
	target, err := prepareReceiveFileTarget(outputPath, header, stderr)
	if err != nil {
		return err
	}
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	progress := NewProgressReporterWithCallback(progressOut, header.Size, progressCallback)
	if progress != nil {
		r = progress.Wrap(r)
	}
	return copyReceiveFile(f, r, header.Size, progress)
}

func prepareReceiveFileTarget(outputPath string, header protocol.Header, stderr io.Writer) (string, error) {
	target, err := ResolveOutputPath(outputPath, header.Name)
	if err != nil {
		return "", err
	}
	if stderr != nil {
		_, _ = fmt.Fprintf(stderr, "Receiving file (%s) into: %q\n", formatProgressBytes(header.Size), filepath.Base(target))
	}
	if err := ensureOutputDir(target); err != nil {
		return "", err
	}
	return target, nil
}

func ensureOutputDir(target string) error {
	dir := filepath.Dir(target)
	if dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func copyReceiveFile(f io.Writer, r io.Reader, size int64, progress *ProgressReporter) error {
	if size <= 0 {
		_, err := io.Copy(f, r)
		if err == nil {
			progress.Finish()
		}
		return err
	}
	copied, err := io.CopyN(f, r, size)
	if err == nil {
		progress.Finish()
	}
	if isIncompleteTransfer(err) {
		return fmt.Errorf("incomplete file transfer: received %s of %s: %w", formatProgressBytes(copied), formatProgressBytes(size), err)
	}
	return err
}

func isIncompleteTransfer(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

type nativeWebFileSink struct {
	outputPath  string
	stderr      io.Writer
	progressOut io.Writer
	progress    *ProgressReporter
	onProgress  func(current, total int64)
	file        *os.File
}

type receiveBlockFileSink struct {
	file     *os.File
	progress *ProgressReporter
	size     int64
	current  atomic.Int64
}

func (s *receiveBlockFileSink) WriteAt(p []byte, off int64) (int, error) {
	if s.file == nil {
		return 0, errors.New("file sink is not open")
	}
	n, err := s.file.WriteAt(p, off)
	if n > 0 {
		s.progress.Add(n)
		if s.current.Add(int64(n)) >= s.size {
			s.progress.Finish()
		}
	}
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (s *receiveBlockFileSink) Close() error {
	if s.file == nil {
		return nil
	}
	if s.current.Load() < s.size {
		s.progress.Abort()
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func newNativeWebFileSink(outputPath string, stderr, progressOut io.Writer, progress func(current, total int64)) *nativeWebFileSink {
	return &nativeWebFileSink{
		outputPath:  outputPath,
		stderr:      stderr,
		progressOut: progressOut,
		onProgress:  progress,
	}
}

func (s *nativeWebFileSink) Open(_ context.Context, meta webproto.Meta) error {
	target, err := ResolveOutputPath(s.outputPath, meta.Name)
	if err != nil {
		return err
	}
	if s.stderr != nil {
		_, _ = fmt.Fprintf(s.stderr, "Receiving file (%s) into: %q\n", formatProgressBytes(meta.Size), filepath.Base(target))
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
	s.progress = NewProgressReporterWithCallback(s.progressOut, meta.Size, s.onProgress)
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

func receiveDirectory(r io.Reader, header protocol.Header, outputPath string, stderr, progressOut io.Writer, progressCallback func(current, total int64)) error {
	destRoot, topLevel, err := ResolveDirectoryOutput(outputPath, header.Name)
	if err != nil {
		return err
	}
	if stderr != nil {
		_, _ = fmt.Fprintf(stderr, "Receiving directory (%s) into: %q/\n", formatProgressBytes(header.Size), topLevel)
		if meta, ok := decodeDirectorySummary(header.Metadata); ok {
			_, _ = fmt.Fprintf(stderr, "%d files, %s (uncompressed)\n", meta.FileCount, formatProgressBytes(meta.UncompressedBytes))
		}
	}
	progress := NewProgressReporterWithCallback(progressOut, header.Size, progressCallback)
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
	if errors.Is(pipeErr, errBlockTransferHandled) {
		return sessionErr
	}
	if sessionErr == nil {
		return pipeErr
	}
	if pipeErr == nil {
		return sessionErr
	}
	if errors.Is(pipeErr, io.ErrClosedPipe) || errors.Is(pipeErr, io.EOF) || errors.Is(pipeErr, io.ErrUnexpectedEOF) {
		return sessionErr
	}
	return pipeErr
}
