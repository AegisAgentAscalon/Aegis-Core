package profilesync

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

func (p *FileObjectProvider) ensure(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ensureLocked(ctx)
}

func (p *FileObjectProvider) ensureLocked(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return sanitizeCloudError(err)
		}
	}
	for _, dir := range []string{p.namespaceRoot(), p.objectsDir()} {
		if err := filepersist.EnsureDir(ctx, dir); err != nil {
			return ErrCloudProviderUnavailable
		}
	}
	return nil
}

func (p *FileObjectProvider) namespaceRoot() string {
	return filepath.Join(p.root, ".aegis-cloud-v2", cloudStorageKey("namespace", p.namespace))
}

// JSON tuples preserve component boundaries; lowercase hashes stay distinct on
// case-insensitive filesystems. The version directory cannot be a legacy namespace.
func cloudStorageKey(parts ...string) string {
	raw, _ := json.Marshal(parts)
	return cloudObjectHash(raw)
}

func (p *FileObjectProvider) legacyRoot() string {
	return filepath.Join(p.root, safeFileComponent(p.namespace))
}

func (p *FileObjectProvider) objectsDir() string {
	return filepath.Join(p.namespaceRoot(), "objects")
}

func (p *FileObjectProvider) objectPath(ref CloudObjectRef) (string, error) {
	if err := ValidateCloudObjectRef(ref); err != nil {
		return "", err
	}
	name := cloudStorageKey("object", ref.ProfileNamespace, string(ref.Kind), ref.ObjectID, ref.Hash) + ".json"
	return filepath.Join(p.objectsDir(), name), nil
}

func (p *FileObjectProvider) legacyObjectPath(ref CloudObjectRef) string {
	name := safeFileComponent(string(ref.Kind)) + "__" + safeFileComponent(ref.ObjectID) + "__" + ref.Hash + ".json"
	return filepath.Join(p.legacyRoot(), "objects", name)
}

func (p *FileObjectProvider) findObjectByIdentityLocked(ctx context.Context, profileNamespace string, kind CloudObjectKind, objectID string) (CloudObjectRef, bool, error) {
	var found CloudObjectRef
	matched := false
	err := p.scanObjectsLocked(ctx, func(ref CloudObjectRef) {
		if ref.ProfileNamespace == profileNamespace && ref.Kind == kind && ref.ObjectID == objectID {
			found, matched = ref, true
		}
	})
	if err != nil {
		return CloudObjectRef{}, false, err
	}
	return found, matched, nil
}

func (p *FileObjectProvider) countObjects(ctx context.Context) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLocked(ctx); err != nil {
		return 0, err
	}
	count := 0
	err := p.scanObjectsLocked(ctx, func(CloudObjectRef) { count++ })
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Legacy files are read-only. Exact embedded identities, never their lossy old
// filenames, determine ownership. Conflicting surviving records fail closed.
// Internal visitors cannot stop the scan: even a found object must not hide
// later corrupt bodies, malformed foreign legacy records, or identity conflicts.
func (p *FileObjectProvider) scanObjectsLocked(ctx context.Context, visit func(CloudObjectRef)) error {
	type identity struct {
		kind CloudObjectKind
		id   string
	}
	seen := make(map[identity]CloudObjectRef)
	objectsDir := p.objectsDir()
	for _, dir := range []string{objectsDir, filepath.Join(p.legacyRoot(), "objects")} {
		if ctx != nil && ctx.Err() != nil {
			return sanitizeCloudError(ctx.Err())
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return ErrCloudProviderUnavailable
		}
		for _, entry := range entries {
			if ctx != nil && ctx.Err() != nil {
				return sanitizeCloudError(ctx.Err())
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			var file objectFile
			if err := readJSONFile(ctx, filepath.Join(dir, entry.Name()), &file); err != nil {
				return ErrCloudStoreCorrupt
			}
			if err := ValidateCloudObjectRef(file.Ref); err != nil || cloudObjectHash(file.Body) != file.Ref.Hash || len(file.Body) != file.Ref.SizeBytes {
				return ErrCloudStoreCorrupt
			}
			if file.Ref.ProfileNamespace != p.namespace {
				if dir == objectsDir {
					return ErrCloudStoreCorrupt
				}
				continue
			}
			if dir == objectsDir {
				expected, _ := p.objectPath(file.Ref)
				if entry.Name() != filepath.Base(expected) {
					return ErrCloudStoreCorrupt
				}
			}
			key := identity{file.Ref.Kind, file.Ref.ObjectID}
			if prior, ok := seen[key]; ok {
				if !sameCloudObjectRef(prior, file.Ref) {
					return ErrCloudObjectConflict
				}
				continue
			}
			seen[key] = file.Ref
			visit(file.Ref)
		}
	}
	return nil
}
