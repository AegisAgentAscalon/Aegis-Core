package devicelink_test

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/pkg/devicelink"
)

func memoryConnection(t *testing.T, handler devicelink.MessageHandler) devicelink.Connection {
	t.Helper()
	transport := devicelink.NewMemoryTransport()
	transport.RegisterHandler("peer", handler)
	conn, err := transport.Open(context.Background(), devicelink.DiscoveredPeer{
		Presence: devicelink.PresenceRecord{DeviceID: "peer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestDirectMemoryTransportOwnsSentAndHandlerMessages(t *testing.T) {
	ctx := context.Background()
	want := devicelink.Message{
		Kind: "request", FromDeviceID: "local", ToDeviceID: "peer",
		Payload: map[string]string{"value": "original"}, CreatedAt: time.Unix(123, 0).UTC(),
	}
	var retained devicelink.Message
	conn := memoryConnection(t, func(_ context.Context, msg devicelink.Message) (devicelink.Message, error) {
		if !reflect.DeepEqual(msg, want) {
			t.Errorf("handler received mutated request: %#v", msg)
		}
		retained = msg
		msg.Payload["value"] = "handler"
		return msg, nil
	})
	input := want
	input.Payload = map[string]string{"value": "original"}
	if err := conn.Send(ctx, input); err != nil {
		t.Fatal(err)
	}
	input.Payload["value"] = "caller after send"
	for i := 0; i < 3; i++ {
		reply, err := conn.Receive(ctx)
		if err != nil || reply.Payload["value"] != "handler" {
			t.Fatalf("receive: %#v, %v", reply, err)
		}
		retained.Payload["value"] = "handler after return"
		if reply.Payload["value"] != "handler" {
			t.Error("handler retained the returned reply payload")
		}
		reply.Payload["value"] = "caller after receive"
		if retained.Payload["value"] != "handler after return" {
			t.Error("reply mutation reached handler-owned payload")
		}
	}
}

func TestDirectMemoryTransportCopiesRetainedRepliesIncludingErrors(t *testing.T) {
	for _, handlerErr := range []error{nil, errors.New("handler failure")} {
		name := "success"
		if handlerErr != nil {
			name = "error"
		}
		t.Run(name, func(t *testing.T) {
			sharedReply := devicelink.Message{Kind: "reply", Payload: map[string]string{"value": "original"}}
			conn := memoryConnection(t, func(context.Context, devicelink.Message) (devicelink.Message, error) {
				return sharedReply, handlerErr
			})
			first, err := conn.Receive(context.Background())
			if err != handlerErr {
				t.Fatalf("handler error identity changed: %v", err)
			}
			first.Payload["value"] = "caller"
			second, err := conn.Receive(context.Background())
			if err != handlerErr || !reflect.DeepEqual(second, sharedReply) || second.Payload["value"] != "original" {
				t.Fatalf("reply mutation contaminated repeated receive: %#v, %v", second, err)
			}
			sharedReply.Payload["value"] = "handler"
			if first.Payload["value"] != "caller" || second.Payload["value"] != "original" {
				t.Fatal("handler mutation reached previously returned replies")
			}
		})
	}
}

func TestDirectMemoryTransportPreservesNilAndEmptyPayloads(t *testing.T) {
	for _, payload := range []map[string]string{nil, {}} {
		wantNil := payload == nil
		name := "empty"
		if wantNil {
			name = "nil"
		}
		t.Run(name, func(t *testing.T) {
			conn := memoryConnection(t, func(_ context.Context, msg devicelink.Message) (devicelink.Message, error) {
				if (msg.Payload == nil) != wantNil || len(msg.Payload) != 0 {
					t.Fatalf("handler payload changed: %#v", msg.Payload)
				}
				return msg, nil
			})
			if err := conn.Send(context.Background(), devicelink.Message{Payload: payload}); err != nil {
				t.Fatal(err)
			}
			reply, err := conn.Receive(context.Background())
			if err != nil || (reply.Payload == nil) != wantNil || len(reply.Payload) != 0 {
				t.Fatalf("reply payload changed: %#v, %v", reply.Payload, err)
			}
		})
	}
}

func TestDirectMemoryTransportConcurrentSendReceiveClose(t *testing.T) {
	ctx := context.Background()
	conn := memoryConnection(t, func(_ context.Context, msg devicelink.Message) (devicelink.Message, error) {
		if msg.Kind != msg.Payload["value"] {
			t.Errorf("inconsistent message snapshot: %#v", msg)
		}
		msg.Payload["handler"] = "owned"
		return msg, nil
	})
	if err := conn.Send(ctx, devicelink.Message{Kind: "initial", Payload: map[string]string{"value": "initial"}}); err != nil {
		t.Fatal(err)
	}
	start, progressed := make(chan struct{}), make(chan struct{}, 8)
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			<-start
			for i := 0; i < 256; i++ {
				var err error
				if worker%2 == 0 {
					value := strconv.Itoa(worker*256 + i)
					err = conn.Send(ctx, devicelink.Message{Kind: value, Payload: map[string]string{"value": value}})
				} else {
					var reply devicelink.Message
					reply, err = conn.Receive(ctx)
					if err == nil {
						reply.Payload["value"] = "caller-owned"
					}
				}
				if err != nil && !errors.Is(err, devicelink.ErrTransportUnavailable) {
					t.Errorf("unexpected operation error: %v", err)
				}
				if i == 0 {
					progressed <- struct{}{}
				}
			}
		}(worker)
	}
	close(start)
	for i := 0; i < 8; i++ {
		<-progressed
	}
	for i := 0; i < 256; i++ {
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := conn.Send(canceled, devicelink.Message{}); err != devicelink.ErrTransportUnavailable {
		t.Fatalf("closed Send must precede cancellation: %v", err)
	}
	if _, err := conn.Receive(canceled); err != devicelink.ErrTransportUnavailable {
		t.Fatalf("closed Receive must precede cancellation: %v", err)
	}
}

func TestDirectMemoryTransportHandlerMayReenterSendAndClose(t *testing.T) {
	ctx := context.Background()
	transport := devicelink.NewMemoryTransport()
	var conn devicelink.Connection
	transport.RegisterHandler("peer", func(ctx context.Context, msg devicelink.Message) (devicelink.Message, error) {
		if err := conn.Send(ctx, devicelink.Message{Kind: "replacement"}); err != nil {
			return devicelink.Message{}, err
		}
		return msg, conn.Close()
	})
	var err error
	conn, err = transport.Open(ctx, devicelink.DiscoveredPeer{Presence: devicelink.PresenceRecord{DeviceID: "peer"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Send(ctx, devicelink.Message{Kind: "original"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		reply, err := conn.Receive(ctx)
		if err == nil && reply.Kind != "original" {
			err = errors.New("reentrant Send replaced the in-flight request")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler reentry blocked behind the connection lock")
	}
	if _, err := conn.Receive(ctx); err != devicelink.ErrTransportUnavailable {
		t.Fatalf("handler did not close the connection: %v", err)
	}
}
