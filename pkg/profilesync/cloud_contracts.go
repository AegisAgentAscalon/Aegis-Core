package profilesync

import (
	"context"
	"errors"
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

type manifestFile struct {
	Manifest CloudProfileManifest `json:"manifest"`
}

type objectFile struct {
	Ref  CloudObjectRef `json:"ref"`
	Body []byte         `json:"body"`
}

var _ CloudProfileSyncProvider = (*FileObjectProvider)(nil)
