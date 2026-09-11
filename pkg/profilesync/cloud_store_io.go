package profilesync

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		if err := os.MkdirAll(dir, 0o700); err != nil {
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

func (p *FileObjectProvider) findObjectByIdentityLocked(profileNamespace string, kind CloudObjectKind, objectID string) (CloudObjectRef, bool, error) {
	refs, err := p.objectRefsLocked()
	if err != nil {
		return CloudObjectRef{}, false, err
	}
	for _, ref := range refs {
		if ref.ProfileNamespace == profileNamespace && ref.Kind == kind && ref.ObjectID == objectID {
			return ref, true, nil
		}
	}
	return CloudObjectRef{}, false, nil
}

// Legacy files are read-only. Exact embedded identities, never their lossy old
// filenames, determine ownership. Conflicting surviving records fail closed.
func (p *FileObjectProvider) objectRefsLocked() ([]CloudObjectRef, error) {
	var refs []CloudObjectRef
	seen := make(map[string]CloudObjectRef)
	for _, dir := range []string{p.objectsDir(), filepath.Join(p.legacyRoot(), "objects")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, ErrCloudProviderUnavailable
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			var file objectFile
			if err := readJSONFile(filepath.Join(dir, entry.Name()), &file); err != nil {
				return nil, ErrCloudStoreCorrupt
			}
			if err := ValidateCloudObjectRef(file.Ref); err != nil || cloudObjectHash(file.Body) != file.Ref.Hash || len(file.Body) != file.Ref.SizeBytes {
				return nil, ErrCloudStoreCorrupt
			}
			if file.Ref.ProfileNamespace != p.namespace {
				if dir == p.objectsDir() {
					return nil, ErrCloudStoreCorrupt
				}
				continue
			}
			if dir == p.objectsDir() {
				expected, _ := p.objectPath(file.Ref)
				if entry.Name() != filepath.Base(expected) {
					return nil, ErrCloudStoreCorrupt
				}
			}
			key := cloudStorageKey("identity", string(file.Ref.Kind), file.Ref.ObjectID)
			if prior, ok := seen[key]; ok {
				if !sameCloudObjectRef(prior, file.Ref) {
					return nil, ErrCloudObjectConflict
				}
				continue
			}
			seen[key] = file.Ref
			refs = append(refs, file.Ref)
		}
	}
	return refs, nil
}
