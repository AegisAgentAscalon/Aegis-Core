package secretstore

import (
	"context"
	"errors"
	"testing"

	public "github.com/AegisAgentAscalon/aegis-core/pkg/secretstore"
)

func TestMemoryStoreConformsToStoreContract(t *testing.T) {
	var store public.Store = NewMemoryStore()
	key := public.Key("auth/sample/token")
	input := []byte("secret")
	if err := store.Put(context.Background(), key, input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'

	got, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("Get() = %q, want defensive copy", got)
	}
	got[0] = 'Y'
	gotAgain, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotAgain) != "secret" {
		t.Fatalf("second Get() = %q, want retained value", gotAgain)
	}

	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), key); !errors.Is(err, public.ErrNotFound) {
		t.Fatalf("Get() after Delete() error = %v, want ErrNotFound", err)
	}
	if err := store.Delete(context.Background(), key); !errors.Is(err, public.ErrNotFound) {
		t.Fatalf("second Delete() error = %v, want ErrNotFound", err)
	}
}
