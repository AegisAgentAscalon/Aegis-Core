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

func TestMemoryStoreVersionedMutationsUsePersistentPerKeyRevisions(t *testing.T) {
	store := NewMemoryStore()
	key := public.Key("auth/session")

	if _, revision, err := store.GetWithRevision(context.Background(), key); !errors.Is(err, public.ErrNotFound) || revision != 0 {
		t.Fatalf("initial versioned get = revision %d, %v", revision, err)
	}
	revision, err := store.CompareAndSwap(context.Background(), key, 0, []byte("first"))
	if err != nil || revision != 1 {
		t.Fatalf("initial CAS = revision %d, %v", revision, err)
	}
	if _, err := store.CompareAndSwap(context.Background(), key, 0, []byte("stale")); !errors.Is(err, public.ErrConflict) {
		t.Fatalf("stale CAS error = %v, want ErrConflict", err)
	}
	got, gotRevision, err := store.GetWithRevision(context.Background(), key)
	if err != nil || gotRevision != revision || string(got) != "first" {
		t.Fatalf("versioned get = %q, revision %d, %v", got, gotRevision, err)
	}

	deletedRevision, err := store.CompareAndDelete(context.Background(), key, revision)
	if err != nil || deletedRevision != 2 {
		t.Fatalf("compare delete = revision %d, %v", deletedRevision, err)
	}
	if _, absentRevision, err := store.GetWithRevision(context.Background(), key); !errors.Is(err, public.ErrNotFound) || absentRevision != deletedRevision {
		t.Fatalf("deleted get = revision %d, %v", absentRevision, err)
	}
	if _, err := store.CompareAndSwap(context.Background(), key, revision, []byte("stale-after-delete")); !errors.Is(err, public.ErrConflict) {
		t.Fatalf("pre-delete revision reused: %v", err)
	}
	recreatedRevision, err := store.CompareAndSwap(context.Background(), key, deletedRevision, []byte("second"))
	if err != nil || recreatedRevision != 3 {
		t.Fatalf("recreate CAS = revision %d, %v", recreatedRevision, err)
	}
	if err := store.Put(context.Background(), key, []byte("base-put")); err != nil {
		t.Fatal(err)
	}
	if _, revisionAfterPut, err := store.GetWithRevision(context.Background(), key); err != nil || revisionAfterPut != 4 {
		t.Fatalf("revision after base Put = %d, %v", revisionAfterPut, err)
	}
	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, revisionAfterDelete, err := store.GetWithRevision(context.Background(), key); !errors.Is(err, public.ErrNotFound) || revisionAfterDelete != 5 {
		t.Fatalf("revision after base Delete = %d, %v", revisionAfterDelete, err)
	}
}
