package profilesync

import (
	"context"
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
	return filepath.Join(p.root, safeFileComponent(p.namespace))
}

func (p *FileObjectProvider) objectsDir() string {
	return filepath.Join(p.namespaceRoot(), "objects")
}

func (p *FileObjectProvider) objectPath(ref CloudObjectRef) (string, error) {
	if err := ValidateCloudObjectRef(ref); err != nil {
		return "", err
	}
	name := safeFileComponent(string(ref.Kind)) + "__" + safeFileComponent(ref.ObjectID) + "__" + ref.Hash + ".json"
	return filepath.Join(p.objectsDir(), name), nil
}

func (p *FileObjectProvider) findObjectByIdentityLocked(profileNamespace string, kind CloudObjectKind, objectID string) (CloudObjectRef, bool, error) {
	entries, err := os.ReadDir(p.objectsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return CloudObjectRef{}, false, nil
		}
		return CloudObjectRef{}, false, ErrCloudProviderUnavailable
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var file objectFile
		if err := readJSONFile(filepath.Join(p.objectsDir(), entry.Name()), &file); err != nil {
			return CloudObjectRef{}, false, ErrCloudStoreCorrupt
		}
		if err := ValidateCloudObjectRef(file.Ref); err != nil || cloudObjectHash(file.Body) != file.Ref.Hash {
			return CloudObjectRef{}, false, ErrCloudStoreCorrupt
		}
		if file.Ref.ProfileNamespace == profileNamespace && file.Ref.Kind == kind && file.Ref.ObjectID == objectID {
			return file.Ref, true, nil
		}
	}
	return CloudObjectRef{}, false, nil
}
