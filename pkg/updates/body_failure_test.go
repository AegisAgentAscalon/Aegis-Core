package updates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
)

type bodyFailureTransport func(*http.Request) (*http.Response, error)

func (f bodyFailureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type failedUpdateBody struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (b failedUpdateBody) Read([]byte) (int, error) {
	if b.cancel != nil {
		b.cancel()
		return 0, b.ctx.Err()
	}
	return 0, errors.New("injected body read failure")
}

func (failedUpdateBody) Close() error { return nil }

func TestHTTPBodyReadFailuresPreserveAuthority(t *testing.T) {
	for _, operation := range []string{"manifest", "artifact"} {
		for _, canceled := range []bool{false, true} {
			name := operation + "/read-failure"
			if canceled {
				name = operation + "/canceled"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				cfg, _, hash := testUpdateFiles(t, "1.2.0")
				cfg.Source = SourceConfig{Provider: ProviderHTTPManifest, ManifestURL: "https://updates.example.test/manifest.json"}
				manifest := testManifest(cfg, "1.2.0", "https://updates.example.test/app.zip", hash)
				raw, err := json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				fail := false
				client := &http.Client{Transport: bodyFailureTransport(func(request *http.Request) (*http.Response, error) {
					var body io.ReadCloser = io.NopCloser(bytes.NewReader(raw))
					if request.URL.Path == "/app.zip" {
						body = io.NopCloser(bytes.NewReader([]byte("artifact 1.2.0")))
					}
					if fail {
						failed := failedUpdateBody{ctx: ctx}
						if canceled {
							failed.cancel = cancel
						}
						body = failed
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: request}, nil
				})}
				svc, err := NewServiceWithOptions(cfg, nil, ServiceOptions{HTTPClient: client})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := svc.CheckForUpdates(ctx); err != nil {
					t.Fatal(err)
				}
				if operation == "artifact" {
					if _, err := svc.DownloadUpdate(ctx, "1.2.0"); err != nil {
						t.Fatal(err)
					}
					if _, err := svc.VerifyUpdate(ctx, "1.2.0"); err != nil {
						t.Fatal(err)
					}
				}
				authority := testNativeSnapshot(t, svc.store).Token
				blobs := testBlobInventory(t, svc.store)
				fail = true
				want := ErrProviderUnavailable
				if operation == "manifest" {
					_, err = svc.CheckForUpdates(ctx)
				} else {
					want = ErrDownloadFailed
					_, err = svc.DownloadUpdate(ctx, "1.2.0")
				}
				if canceled {
					want = ErrContextCanceled
				}
				if !errors.Is(err, want) {
					t.Fatalf("body read error = %v, want %v", err, want)
				}
				if authority != testNativeSnapshot(t, svc.store).Token || !reflect.DeepEqual(blobs, testBlobInventory(t, svc.store)) {
					t.Fatal("failed body read changed authority or retained prepared artifact bytes")
				}
			})
		}
	}
}
