//go:build js && wasm

package main

import (
	"context"
	"errors"
	"sync"
	"syscall/js"

	"github.com/shayne/derpcat/pkg/derphole/webproto"
	"github.com/shayne/derpcat/pkg/derphole/webrelay"
)

var (
	funcs   []js.Func
	offerMu sync.Mutex
	offer   *webrelay.Offer
)

func main() {
	api := js.Global().Get("Object").New()
	api.Set("createOffer", keep(js.FuncOf(createOffer)))
	api.Set("sendFile", keep(js.FuncOf(sendFile)))
	api.Set("receiveFile", keep(js.FuncOf(receiveFile)))
	api.Set("cancel", keep(js.FuncOf(cancelOffer)))
	js.Global().Set("derpholeWASM", api)

	select {}
}

func createOffer(this js.Value, args []js.Value) any {
	return promise(func(ctx context.Context) (any, error) {
		next, tok, err := webrelay.NewOffer(ctx)
		if err != nil {
			return nil, err
		}
		offerMu.Lock()
		if offer != nil {
			_ = offer.Close()
		}
		offer = next
		offerMu.Unlock()
		return tok, nil
	})
}

func sendFile(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return rejected("sendFile requires a File and callbacks")
	}
	file := args[0]
	callbacks := newCallbacks(args[1])
	return promise(func(ctx context.Context) (any, error) {
		offerMu.Lock()
		current := offer
		offer = nil
		offerMu.Unlock()
		if current == nil {
			return nil, errors.New("no active offer")
		}
		defer current.Close()
		var direct webrelay.DirectTransport
		if len(args) >= 3 {
			direct = newJSDirectTransport(args[2])
		}
		err := current.SendWithOptions(ctx, jsFileSource{file: file}, callbacks, webrelay.TransferOptions{Direct: direct})
		return nil, err
	})
}

func receiveFile(this js.Value, args []js.Value) any {
	if len(args) < 3 {
		return rejected("receiveFile requires a token, sink, and callbacks")
	}
	tok := args[0].String()
	sink := &jsFileSink{api: args[1]}
	callbacks := newCallbacks(args[2])
	return promise(func(ctx context.Context) (any, error) {
		var direct webrelay.DirectTransport
		if len(args) >= 4 {
			direct = newJSDirectTransport(args[3])
		}
		return nil, webrelay.ReceiveWithOptions(ctx, tok, sink, callbacks, webrelay.TransferOptions{Direct: direct})
	})
}

func cancelOffer(this js.Value, args []js.Value) any {
	offerMu.Lock()
	current := offer
	offer = nil
	offerMu.Unlock()
	if current != nil {
		_ = current.Close()
	}
	return nil
}

type jsFileSource struct {
	file js.Value
}

func (s jsFileSource) Name() string {
	return s.file.Get("name").String()
}

func (s jsFileSource) Size() int64 {
	return int64(s.file.Get("size").Float())
}

func (s jsFileSource) ReadChunk(ctx context.Context, offset int64, max int) ([]byte, error) {
	size := s.Size()
	if offset >= size {
		return nil, nil
	}
	end := offset + int64(max)
	if end > size {
		end = size
	}
	blob := s.file.Call("slice", float64(offset), float64(end))
	buf, err := await(ctx, blob.Call("arrayBuffer"))
	if err != nil {
		return nil, err
	}
	u8 := js.Global().Get("Uint8Array").New(buf)
	out := make([]byte, u8.Get("byteLength").Int())
	js.CopyBytesToGo(out, u8)
	return out, nil
}

type jsFileSink struct {
	api    js.Value
	writer js.Value
}

func (s *jsFileSink) Open(ctx context.Context, meta webproto.Meta) error {
	open := s.api.Get("open")
	if open.Type() != js.TypeFunction {
		return errors.New("sink.open is not a function")
	}
	writer, err := await(ctx, open.Invoke(meta.Name, float64(meta.Size)))
	if err != nil {
		return err
	}
	s.writer = writer
	return nil
}

func (s *jsFileSink) WriteChunk(ctx context.Context, chunk []byte) error {
	write := s.writer.Get("write")
	if write.Type() != js.TypeFunction {
		return errors.New("writer.write is not a function")
	}
	u8 := js.Global().Get("Uint8Array").New(len(chunk))
	js.CopyBytesToJS(u8, chunk)
	_, err := await(ctx, write.Invoke(u8))
	return err
}

func (s *jsFileSink) Close(ctx context.Context) error {
	closeFn := s.writer.Get("close")
	if closeFn.Type() != js.TypeFunction {
		return nil
	}
	_, err := await(ctx, closeFn.Invoke())
	return err
}

func newCallbacks(v js.Value) webrelay.Callbacks {
	return webrelay.Callbacks{
		Status: func(status string) {
			call(v, "status", status)
		},
		Progress: func(progress webrelay.Progress) {
			call(v, "progress", float64(progress.Bytes), float64(progress.Total))
		},
		Trace: func(trace string) {
			call(v, "trace", trace)
		},
	}
}

func call(v js.Value, name string, args ...any) {
	fn := v.Get(name)
	if fn.Type() == js.TypeFunction {
		fn.Invoke(args...)
	}
}

func promise(run func(context.Context) (any, error)) js.Value {
	promiseCtor := js.Global().Get("Promise")
	return promiseCtor.New(js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve := args[0]
		reject := args[1]
		go func() {
			result, err := run(context.Background())
			if err != nil {
				reject.Invoke(jsError(err.Error()))
				return
			}
			if result == nil {
				resolve.Invoke(js.Undefined())
				return
			}
			resolve.Invoke(result)
		}()
		return nil
	}))
}

func rejected(message string) js.Value {
	return js.Global().Get("Promise").Call("reject", jsError(message))
}

func await(ctx context.Context, promise js.Value) (js.Value, error) {
	type result struct {
		value js.Value
		err   error
	}
	ch := make(chan result, 1)
	then := js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- result{value: args[0]}
		return nil
	})
	catch := js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- result{err: jsValueError(args[0])}
		return nil
	})
	defer then.Release()
	defer catch.Release()
	promise.Call("then", then).Call("catch", catch)
	select {
	case res := <-ch:
		return res.value, res.err
	case <-ctx.Done():
		return js.Value{}, ctx.Err()
	}
}

func jsValueError(v js.Value) error {
	if v.Type() == js.TypeObject {
		msg := v.Get("message")
		if msg.Truthy() {
			return errors.New(msg.String())
		}
	}
	return errors.New(v.String())
}

func jsError(message string) js.Value {
	return js.Global().Get("Error").New(message)
}

func keep(fn js.Func) js.Func {
	funcs = append(funcs, fn)
	return fn
}
