package profilesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	CloudManifestSchemaVersion = 1
	DefaultMaxSyncObjectBytes  = 1 << 20
)

var (
	ErrCloudProviderUnavailable = errors.New("profile sync cloud provider unavailable")
	ErrCloudObjectNotFound      = errors.New("profile sync cloud object is not available")
	ErrInvalidCloudManifest     = errors.New("invalid profile sync cloud manifest")
	ErrInvalidCloudObject       = errors.New("invalid profile sync cloud object")
	ErrCloudHashMismatch        = errors.New("profile sync cloud object hash mismatch")
	ErrCloudObjectTooLarge      = errors.New("profile sync cloud object is too large")
	ErrCloudStoreCorrupt        = errors.New("profile sync cloud store is corrupt")
	ErrCloudObjectConflict      = errors.New("profile sync cloud object id conflict")
)

type CloudObjectKind string

const (
	CloudObjectSnapshotMetadata   CloudObjectKind = "snapshot_metadata"
	CloudObjectProposalMetadata   CloudObjectKind = "proposal_metadata"
	CloudObjectConflictMetadata   CloudObjectKind = "conflict_metadata"
	CloudObjectResourceDescriptor CloudObjectKind = "resource_descriptor_metadata"
	CloudObjectManifestMetadata   CloudObjectKind = "manifest_metadata"
)

type CloudManifestRelation string

const (
	CloudManifestInvalid                CloudManifestRelation = "invalid_manifest"
	CloudManifestLocalMissing           CloudManifestRelation = "local_missing_remote_available"
	CloudManifestRemoteNewer            CloudManifestRelation = "remote_newer"
	CloudManifestSame                   CloudManifestRelation = "same_manifest"
	CloudManifestRemoteStale            CloudManifestRelation = "remote_stale"
	CloudManifestRemoteFutureDated      CloudManifestRelation = "remote_future_dated"
	CloudManifestSameGenerationConflict CloudManifestRelation = "same_generation_conflict"
)

type CloudObjectRef struct {
	ProfileNamespace string          `json:"profile_namespace"`
	ObjectID         string          `json:"object_id"`
	Kind             CloudObjectKind `json:"kind"`
	Hash             string          `json:"hash"`
	SizeBytes        int             `json:"size_bytes"`
	CreatedAt        time.Time       `json:"created_at"`
}

type CloudSyncObject struct {
	ProfileNamespace string            `json:"profile_namespace"`
	ObjectID         string            `json:"object_id"`
	Kind             CloudObjectKind   `json:"kind"`
	Body             []byte            `json:"body"`
	CreatedAt        time.Time         `json:"created_at"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type CloudObjectQuery struct {
	ProfileNamespace string          `json:"profile_namespace"`
	Kind             CloudObjectKind `json:"kind,omitempty"`
}

type CloudProfileManifest struct {
	SchemaVersion          int              `json:"schema_version"`
	ProfileNamespace       string           `json:"profile_namespace"`
	ManifestID             string           `json:"manifest_id"`
	Generation             int64            `json:"generation"`
	CreatedAt              time.Time        `json:"created_at"`
	PreviousManifestHash   string           `json:"previous_manifest_hash,omitempty"`
	LatestSnapshotRef      *CloudObjectRef  `json:"latest_snapshot_ref,omitempty"`
	ProposalRefs           []CloudObjectRef `json:"proposal_refs,omitempty"`
	ConflictRefs           []CloudObjectRef `json:"conflict_refs,omitempty"`
	ResourceDescriptorRefs []CloudObjectRef `json:"resource_descriptor_refs,omitempty"`
	ManifestHash           string           `json:"manifest_hash,omitempty"`
	SignerDeviceID         string           `json:"signer_device_id,omitempty"`
	SignerKeyFingerprint   string           `json:"signer_key_fingerprint,omitempty"`
	ReviewRequired         bool             `json:"review_required"`
}

type CloudSyncIssue struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}

type CloudSyncProviderStatus struct {
	Available        bool             `json:"available"`
	ProviderID       string           `json:"provider_id,omitempty"`
	ProfileNamespace string           `json:"profile_namespace,omitempty"`
	ManifestCount    int              `json:"manifest_count"`
	ObjectCount      int              `json:"object_count"`
	Summary          string           `json:"summary,omitempty"`
	Issues           []CloudSyncIssue `json:"issues,omitempty"`
}

type CloudManifestComparison struct {
	Relation         CloudManifestRelation `json:"relation"`
	ReviewRequired   bool                  `json:"review_required"`
	LocalHash        string                `json:"local_hash,omitempty"`
	RemoteHash       string                `json:"remote_hash,omitempty"`
	LocalGeneration  int64                 `json:"local_generation,omitempty"`
	RemoteGeneration int64                 `json:"remote_generation,omitempty"`
	Issues           []CloudSyncIssue      `json:"issues,omitempty"`
}

type CloudManifestObjectVerification struct {
	Verified       bool             `json:"verified"`
	CheckedObjects int              `json:"checked_objects"`
	MissingObjects int              `json:"missing_objects"`
	HashMismatches int              `json:"hash_mismatches"`
	InvalidObjects int              `json:"invalid_objects"`
	Issues         []CloudSyncIssue `json:"issues,omitempty"`
}

type CloudProfileSyncProvider interface {
	GetStatus(ctx context.Context) CloudSyncProviderStatus
	GetManifest(ctx context.Context, profileNamespace string) (CloudProfileManifest, error)
	PutManifest(ctx context.Context, manifest CloudProfileManifest) error
	GetObject(ctx context.Context, ref CloudObjectRef) ([]byte, error)
	PutObject(ctx context.Context, object CloudSyncObject) (CloudObjectRef, error)
	ListObjects(ctx context.Context, query CloudObjectQuery) ([]CloudObjectRef, error)
}

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

type manifestFile struct {
	Manifest CloudProfileManifest `json:"manifest"`
}

type objectFile struct {
	Ref  CloudObjectRef `json:"ref"`
	Body []byte         `json:"body"`
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

func NormalizeCloudManifest(manifest CloudProfileManifest) (CloudProfileManifest, error) {
	if manifest.SchemaVersion == 0 {
		manifest.SchemaVersion = CloudManifestSchemaVersion
	}
	if manifest.SchemaVersion != CloudManifestSchemaVersion || !validSyncName(manifest.ProfileNamespace) || !validSyncID(manifest.ManifestID) || manifest.Generation < 0 || manifest.CreatedAt.IsZero() {
		return CloudProfileManifest{}, ErrInvalidCloudManifest
	}
	if err := validateCloudManifestCredentialBoundary(manifest); err != nil {
		return CloudProfileManifest{}, err
	}
	manifest.ProposalRefs = append([]CloudObjectRef{}, manifest.ProposalRefs...)
	manifest.ConflictRefs = append([]CloudObjectRef{}, manifest.ConflictRefs...)
	manifest.ResourceDescriptorRefs = append([]CloudObjectRef{}, manifest.ResourceDescriptorRefs...)
	if manifest.LatestSnapshotRef != nil {
		if err := validateCloudManifestRef(manifest.ProfileNamespace, *manifest.LatestSnapshotRef, CloudObjectSnapshotMetadata); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	seenRefs := make(map[string]struct{})
	if manifest.LatestSnapshotRef != nil {
		if err := recordCloudManifestRefIdentity(seenRefs, *manifest.LatestSnapshotRef); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	for _, ref := range manifest.ProposalRefs {
		if err := validateCloudManifestRef(manifest.ProfileNamespace, ref, CloudObjectProposalMetadata); err != nil {
			return CloudProfileManifest{}, err
		}
		if err := recordCloudManifestRefIdentity(seenRefs, ref); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	for _, ref := range manifest.ConflictRefs {
		if err := validateCloudManifestRef(manifest.ProfileNamespace, ref, CloudObjectConflictMetadata); err != nil {
			return CloudProfileManifest{}, err
		}
		if err := recordCloudManifestRefIdentity(seenRefs, ref); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	for _, ref := range manifest.ResourceDescriptorRefs {
		if err := validateCloudManifestRef(manifest.ProfileNamespace, ref, CloudObjectResourceDescriptor); err != nil {
			return CloudProfileManifest{}, err
		}
		if err := recordCloudManifestRefIdentity(seenRefs, ref); err != nil {
			return CloudProfileManifest{}, err
		}
	}
	expected := cloudManifestHash(manifest)
	if manifest.ManifestHash == "" {
		manifest.ManifestHash = expected
	}
	if manifest.ManifestHash != expected {
		return CloudProfileManifest{}, ErrCloudHashMismatch
	}
	return manifest, nil
}

func CompareCloudManifests(local *CloudProfileManifest, remote CloudProfileManifest, now time.Time) CloudManifestComparison {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	remoteNormalized, err := NormalizeCloudManifest(remote)
	if err != nil {
		return cloudManifestComparison(CloudManifestInvalid, false, nil, nil, cloudIssue("invalid_remote_manifest", err, true))
	}
	if remoteNormalized.CreatedAt.After(now.Add(defaultClockSkew)) {
		return cloudManifestComparison(CloudManifestRemoteFutureDated, true, nil, &remoteNormalized, cloudIssue("remote_manifest_future_dated", ErrInvalidCloudManifest, true))
	}
	if local == nil || strings.TrimSpace(local.ManifestID) == "" {
		return cloudManifestComparison(CloudManifestLocalMissing, false, nil, &remoteNormalized)
	}
	localNormalized, err := NormalizeCloudManifest(*local)
	if err != nil {
		return cloudManifestComparison(CloudManifestInvalid, true, local, &remoteNormalized, cloudIssue("invalid_local_manifest", err, true))
	}
	switch {
	case remoteNormalized.Generation > localNormalized.Generation:
		return cloudManifestComparison(CloudManifestRemoteNewer, false, &localNormalized, &remoteNormalized)
	case remoteNormalized.Generation < localNormalized.Generation:
		return cloudManifestComparison(CloudManifestRemoteStale, true, &localNormalized, &remoteNormalized, cloudIssue("remote_manifest_stale", ErrInvalidCloudManifest, false))
	case remoteNormalized.ManifestHash == localNormalized.ManifestHash:
		return cloudManifestComparison(CloudManifestSame, false, &localNormalized, &remoteNormalized)
	default:
		return cloudManifestComparison(CloudManifestSameGenerationConflict, true, &localNormalized, &remoteNormalized, cloudIssue("remote_manifest_conflict", ErrConflictReview, true))
	}
}

func VerifyCloudManifestObjects(ctx context.Context, provider CloudProfileSyncProvider, manifest CloudProfileManifest) CloudManifestObjectVerification {
	if provider == nil {
		return CloudManifestObjectVerification{Verified: false, InvalidObjects: 1, Issues: []CloudSyncIssue{cloudIssue("cloud_provider_missing", ErrCloudProviderUnavailable, true)}}
	}
	manifest, err := NormalizeCloudManifest(manifest)
	if err != nil {
		return CloudManifestObjectVerification{Verified: false, InvalidObjects: 1, Issues: []CloudSyncIssue{cloudIssue("invalid_manifest", err, true)}}
	}
	result := CloudManifestObjectVerification{Verified: true}
	for _, expected := range cloudManifestRefs(manifest) {
		result.CheckedObjects++
		body, err := provider.GetObject(ctx, expected)
		if err != nil {
			result.Verified = false
			switch {
			case errors.Is(err, ErrCloudObjectNotFound):
				result.MissingObjects++
				result.Issues = append(result.Issues, cloudIssue("cloud_object_missing", err, true))
			case errors.Is(err, ErrCloudHashMismatch):
				result.HashMismatches++
				result.Issues = append(result.Issues, cloudIssue("cloud_object_hash_mismatch", err, true))
			default:
				result.InvalidObjects++
				result.Issues = append(result.Issues, cloudIssue("cloud_object_invalid", err, true))
			}
			continue
		}
		if len(body) != expected.SizeBytes || cloudObjectHash(body) != expected.Hash || expected.ProfileNamespace != manifest.ProfileNamespace {
			result.Verified = false
			result.HashMismatches++
			result.Issues = append(result.Issues, cloudIssue("cloud_object_hash_mismatch", ErrCloudHashMismatch, true))
		}
	}
	return result
}

func ValidateCloudObject(object CloudSyncObject, maxBytes int) (CloudObjectRef, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSyncObjectBytes
	}
	if !validSyncName(object.ProfileNamespace) || !validSyncID(object.ObjectID) || !validCloudObjectKind(object.Kind) || object.CreatedAt.IsZero() {
		return CloudObjectRef{}, ErrInvalidCloudObject
	}
	if len(object.Body) == 0 || len(object.Body) > maxBytes {
		if len(object.Body) > maxBytes {
			return CloudObjectRef{}, ErrCloudObjectTooLarge
		}
		return CloudObjectRef{}, ErrInvalidCloudObject
	}
	if err := ValidateCloudObjectMetadata(object.Metadata); err != nil {
		return CloudObjectRef{}, err
	}
	return CloudObjectRef{ProfileNamespace: object.ProfileNamespace, ObjectID: object.ObjectID, Kind: object.Kind, Hash: cloudObjectHash(object.Body), SizeBytes: len(object.Body), CreatedAt: object.CreatedAt}, nil
}

func validateCloudManifestRef(profileNamespace string, ref CloudObjectRef, kind CloudObjectKind) error {
	if err := ValidateCloudObjectRef(ref); err != nil {
		return err
	}
	if ref.ProfileNamespace != profileNamespace || ref.Kind != kind {
		return ErrInvalidCloudManifest
	}
	return nil
}

func recordCloudManifestRefIdentity(seen map[string]struct{}, ref CloudObjectRef) error {
	key := ref.ProfileNamespace + "\x00" + string(ref.Kind) + "\x00" + ref.ObjectID
	if _, ok := seen[key]; ok {
		return ErrCloudObjectConflict
	}
	seen[key] = struct{}{}
	return nil
}

func ValidateCloudObjectRef(ref CloudObjectRef) error {
	if !validSyncName(ref.ProfileNamespace) || !validSyncID(ref.ObjectID) || !validCloudObjectKind(ref.Kind) || !validHash(ref.Hash) || ref.SizeBytes <= 0 || ref.SizeBytes > DefaultMaxSyncObjectBytes || ref.CreatedAt.IsZero() {
		return ErrInvalidCloudObject
	}
	return nil
}

func ValidateCloudObjectMetadata(metadata map[string]string) error {
	for k, v := range metadata {
		if !validSyncName(k) || unsafeSyncText(k) || unsafeSyncText(v) {
			return ErrInvalidCloudObject
		}
	}
	return nil
}

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

func cloudManifestComparison(relation CloudManifestRelation, review bool, local, remote *CloudProfileManifest, issues ...CloudSyncIssue) CloudManifestComparison {
	out := CloudManifestComparison{Relation: relation, ReviewRequired: review, Issues: issues}
	if local != nil {
		out.LocalHash = local.ManifestHash
		out.LocalGeneration = local.Generation
	}
	if remote != nil {
		out.RemoteHash = remote.ManifestHash
		out.RemoteGeneration = remote.Generation
	}
	return out
}

func cloudManifestRefs(manifest CloudProfileManifest) []CloudObjectRef {
	refs := make([]CloudObjectRef, 0, 1+len(manifest.ProposalRefs)+len(manifest.ConflictRefs)+len(manifest.ResourceDescriptorRefs))
	if manifest.LatestSnapshotRef != nil {
		refs = append(refs, *manifest.LatestSnapshotRef)
	}
	refs = append(refs, manifest.ProposalRefs...)
	refs = append(refs, manifest.ConflictRefs...)
	refs = append(refs, manifest.ResourceDescriptorRefs...)
	return refs
}

func sameCloudObjectRef(a, b CloudObjectRef) bool {
	return a.ProfileNamespace == b.ProfileNamespace &&
		a.ObjectID == b.ObjectID &&
		a.Kind == b.Kind &&
		a.Hash == b.Hash &&
		a.SizeBytes == b.SizeBytes &&
		a.CreatedAt.Equal(b.CreatedAt)
}

func cloudObjectHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func cloudManifestHash(manifest CloudProfileManifest) string {
	copy := manifest
	copy.ManifestHash = ""
	raw, _ := json.Marshal(copy)
	return cloudObjectHash(raw)
}

func validCloudObjectKind(kind CloudObjectKind) bool {
	switch kind {
	case CloudObjectSnapshotMetadata, CloudObjectProposalMetadata, CloudObjectConflictMetadata, CloudObjectResourceDescriptor, CloudObjectManifestMetadata:
		return true
	default:
		return false
	}
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func safeFileComponent(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, ":", "_")
	if !validSyncID(value) || strings.Contains(value, "/") || strings.Contains(value, `\`) || strings.Contains(value, "..") {
		return "invalid"
	}
	return value
}

func cloudIssue(code string, err error, blocking bool) CloudSyncIssue {
	return sanitizeCloudIssue(CloudSyncIssue{Code: code, Message: sanitizeCloudError(err).Error(), Blocking: blocking})
}

func sanitizeCloudProviderStatus(status CloudSyncProviderStatus) CloudSyncProviderStatus {
	out := CloudSyncProviderStatus{
		Available:        status.Available,
		ProviderID:       safeID(status.ProviderID),
		ProfileNamespace: safeID(status.ProfileNamespace),
		Summary:          safeSummary(status.Summary, "profile sync cloud provider status"),
	}
	if status.ManifestCount > 0 {
		out.ManifestCount = status.ManifestCount
	}
	if status.ObjectCount > 0 {
		out.ObjectCount = status.ObjectCount
	}
	for _, issue := range status.Issues {
		out.Issues = append(out.Issues, sanitizeCloudIssue(issue))
	}
	if !out.Available && len(out.Issues) == 0 {
		out.Issues = append(out.Issues, cloudIssue("cloud_provider_unavailable", ErrCloudProviderUnavailable, false))
	}
	return out
}

func sanitizeCloudIssue(issue CloudSyncIssue) CloudSyncIssue {
	code := safeID(issue.Code)
	if code == "" {
		code = "cloud_sync_issue"
	}
	return CloudSyncIssue{Code: code, Message: safeSummary(issue.Message, ErrCloudProviderUnavailable.Error()), Blocking: issue.Blocking}
}

func validateCloudManifestCredentialBoundary(manifest CloudProfileManifest) error {
	if manifest.SignerDeviceID != "" && !validSyncID(manifest.SignerDeviceID) {
		return ErrInvalidCloudManifest
	}
	if manifest.SignerKeyFingerprint != "" && !validHash(manifest.SignerKeyFingerprint) {
		return ErrInvalidCloudManifest
	}
	return nil
}

func ctxBackground() context.Context {
	return context.Background()
}

func sanitizeCloudError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return ErrTransportUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTransportUnavailable
	}
	switch {
	case errors.Is(err, ErrCloudObjectNotFound):
		return ErrCloudObjectNotFound
	case errors.Is(err, ErrInvalidCloudManifest):
		return ErrInvalidCloudManifest
	case errors.Is(err, ErrInvalidCloudObject):
		return ErrInvalidCloudObject
	case errors.Is(err, ErrCloudHashMismatch):
		return ErrCloudHashMismatch
	case errors.Is(err, ErrCloudObjectTooLarge):
		return ErrCloudObjectTooLarge
	case errors.Is(err, ErrCloudStoreCorrupt):
		return ErrCloudStoreCorrupt
	case errors.Is(err, ErrCloudObjectConflict):
		return ErrCloudObjectConflict
	default:
		return ErrCloudProviderUnavailable
	}
}

var _ CloudProfileSyncProvider = (*FileObjectProvider)(nil)
