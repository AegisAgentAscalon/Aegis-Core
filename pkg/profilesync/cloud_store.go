package profilesync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type FileObjectProviderConfig struct {
	RootDir          string
	ProviderID       string
	ProfileNamespace string
	MaxObjectBytes   int
	Clock            Clock
}

type FileObjectProvider struct {
	mu        sync.Mutex
	root      string
	provider  string
	namespace string
	maxBytes  int
	clock     Clock
}

func NewFileObjectProvider(config FileObjectProviderConfig) (*FileObjectProvider, error) {
	root := strings.TrimSpace(config.RootDir)
	if root == "" || !validSyncName(config.ProfileNamespace) {
		return nil, ErrInvalidConfig
	}
	providerID := strings.TrimSpace(config.ProviderID)
	if providerID == "" {
		providerID = "file-object-provider"
	}
	if !validSyncName(providerID) {
		return nil, ErrInvalidConfig
	}
	maxBytes := config.MaxObjectBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSyncObjectBytes
	}
	if maxBytes > DefaultMaxSyncObjectBytes {
		return nil, ErrInvalidConfig
	}
	p := &FileObjectProvider{root: filepath.Clean(root), provider: providerID, namespace: config.ProfileNamespace, maxBytes: maxBytes, clock: config.Clock}
	if err := p.ensure(ctxBackground()); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *FileObjectProvider) GetStatus(ctx context.Context) CloudSyncProviderStatus {
	if p == nil {
		return sanitizeCloudProviderStatus(CloudSyncProviderStatus{Available: false, Summary: ErrCloudProviderUnavailable.Error(), Issues: []CloudSyncIssue{cloudIssue("cloud_provider_missing", ErrCloudProviderUnavailable, false)}})
	}
	status := CloudSyncProviderStatus{Available: true, ProviderID: p.provider, ProfileNamespace: p.namespace, Summary: "profile sync cloud-compatible object provider is available"}
	if err := p.ensure(ctx); err != nil {
		status.Available = false
		status.Summary = "profile sync cloud-compatible object provider is degraded"
		status.Issues = append(status.Issues, cloudIssue("cloud_provider_unavailable", err, false))
		return sanitizeCloudProviderStatus(status)
	}
	if manifest, err := p.GetManifest(ctx, p.namespace); err == nil && manifest.ManifestID != "" {
		status.ManifestCount = 1
	} else if err != nil && !errors.Is(err, ErrCloudObjectNotFound) {
		status.Available = false
		status.Issues = append(status.Issues, cloudIssue("cloud_manifest_unavailable", err, false))
	}
	if refs, err := p.ListObjects(ctx, CloudObjectQuery{ProfileNamespace: p.namespace}); err == nil {
		status.ObjectCount = len(refs)
	} else {
		status.Available = false
		status.Issues = append(status.Issues, cloudIssue("cloud_objects_unavailable", err, false))
	}
	return sanitizeCloudProviderStatus(status)
}

func (p *FileObjectProvider) PutManifest(ctx context.Context, manifest CloudProfileManifest) error {
	if p == nil {
		return ErrCloudProviderUnavailable
	}
	manifest, err := NormalizeCloudManifest(manifest)
	if err != nil {
		return err
	}
	if manifest.ProfileNamespace != p.namespace {
		return ErrInvalidCloudManifest
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLocked(ctx); err != nil {
		return err
	}
	return writeJSONAtomic(filepath.Join(p.namespaceRoot(), "manifest.json"), manifestFile{Manifest: manifest})
}

func (p *FileObjectProvider) GetManifest(ctx context.Context, profileNamespace string) (CloudProfileManifest, error) {
	if p == nil {
		return CloudProfileManifest{}, ErrCloudProviderUnavailable
	}
	if profileNamespace != p.namespace || !validSyncName(profileNamespace) {
		return CloudProfileManifest{}, ErrInvalidCloudManifest
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLocked(ctx); err != nil {
		return CloudProfileManifest{}, err
	}
	var file manifestFile
	if err := readJSONFile(filepath.Join(p.namespaceRoot(), "manifest.json"), &file); err != nil {
		if errors.Is(err, ErrLocalStoreNotFound) {
			return CloudProfileManifest{}, ErrCloudObjectNotFound
		}
		return CloudProfileManifest{}, ErrCloudStoreCorrupt
	}
	manifest, err := NormalizeCloudManifest(file.Manifest)
	if err != nil {
		return CloudProfileManifest{}, ErrCloudStoreCorrupt
	}
	return manifest, nil
}

func (p *FileObjectProvider) PutObject(ctx context.Context, object CloudSyncObject) (CloudObjectRef, error) {
	if p == nil {
		return CloudObjectRef{}, ErrCloudProviderUnavailable
	}
	ref, err := ValidateCloudObject(object, p.maxBytes)
	if err != nil {
		return CloudObjectRef{}, err
	}
	if object.ProfileNamespace != p.namespace {
		return CloudObjectRef{}, ErrInvalidCloudObject
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLocked(ctx); err != nil {
		return CloudObjectRef{}, err
	}
	existing, ok, err := p.findObjectByIdentityLocked(ref.ProfileNamespace, ref.Kind, ref.ObjectID)
	if err != nil {
		return CloudObjectRef{}, err
	}
	if ok {
		if existing.Hash == ref.Hash {
			return existing, nil
		}
		return CloudObjectRef{}, ErrCloudObjectConflict
	}
	path, err := p.objectPath(ref)
	if err != nil {
		return CloudObjectRef{}, err
	}
	return ref, writeJSONAtomic(path, objectFile{Ref: ref, Body: append([]byte{}, object.Body...)})
}

func (p *FileObjectProvider) GetObject(ctx context.Context, ref CloudObjectRef) ([]byte, error) {
	if p == nil {
		return nil, ErrCloudProviderUnavailable
	}
	if err := ValidateCloudObjectRef(ref); err != nil || ref.ProfileNamespace != p.namespace {
		return nil, ErrInvalidCloudObject
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLocked(ctx); err != nil {
		return nil, err
	}
	path, err := p.objectPath(ref)
	if err != nil {
		return nil, err
	}
	var file objectFile
	if err := readJSONFile(path, &file); err != nil {
		if errors.Is(err, ErrLocalStoreNotFound) {
			return nil, ErrCloudObjectNotFound
		}
		return nil, ErrCloudStoreCorrupt
	}
	if err := ValidateCloudObjectRef(file.Ref); err != nil || !sameCloudObjectRef(file.Ref, ref) || cloudObjectHash(file.Body) != ref.Hash {
		return nil, ErrCloudHashMismatch
	}
	return append([]byte{}, file.Body...), nil
}

func (p *FileObjectProvider) ListObjects(ctx context.Context, query CloudObjectQuery) ([]CloudObjectRef, error) {
	if p == nil {
		return nil, ErrCloudProviderUnavailable
	}
	if query.ProfileNamespace != p.namespace || !validSyncName(query.ProfileNamespace) {
		return nil, ErrInvalidCloudObject
	}
	if query.Kind != "" && !validCloudObjectKind(query.Kind) {
		return nil, ErrInvalidCloudObject
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLocked(ctx); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(p.objectsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, ErrCloudProviderUnavailable
	}
	var refs []CloudObjectRef
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var file objectFile
		if err := readJSONFile(filepath.Join(p.objectsDir(), entry.Name()), &file); err != nil {
			return nil, ErrCloudStoreCorrupt
		}
		if err := ValidateCloudObjectRef(file.Ref); err != nil || file.Ref.ProfileNamespace != p.namespace || cloudObjectHash(file.Body) != file.Ref.Hash {
			return nil, ErrCloudStoreCorrupt
		}
		if query.Kind == "" || file.Ref.Kind == query.Kind {
			refs = append(refs, file.Ref)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ObjectID < refs[j].ObjectID })
	return refs, nil
}

func ctxBackground() context.Context {
	return context.Background()
}
