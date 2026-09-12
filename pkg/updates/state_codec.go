package updates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/AegisAgentAscalon/aegis-core/internal/filepersist"
)

const candidateInvalid = "legacy_candidate_invalid"

type authorityRef struct {
	Manifest  string `json:"manifest"`
	Artifact  int    `json:"artifact"`
	SourceKey string `json:"source_key"`
	PolicyKey string `json:"policy_key"`
}
type selectedRef struct {
	authorityRef
	UpdatedAt time.Time `json:"updated_at"`
}
type transferRef struct {
	authorityRef
	Blob         string    `json:"blob"`
	BytesWritten int64     `json:"bytes_written"`
	DownloadedAt time.Time `json:"downloaded_at"`
}
type verifiedRef struct {
	Transfer   string    `json:"transfer"`
	VerifiedAt time.Time `json:"verified_at"`
}
type stagedRef struct {
	authorityRef
	// Preserve legacy public spelling when it differs only in SHA-256 case.
	SHA256   string        `json:"sha256,omitempty"`
	Source   SourceSummary `json:"source"`
	Blob     string        `json:"blob"`
	Size     int64         `json:"size"`
	StagedAt time.Time     `json:"staged_at"`
}
type blobRecord struct {
	Filename string `json:"filename"`
	Role     string `json:"role"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}
type stateRecord struct {
	Version        int                    `json:"version"`
	CandidateFault string                 `json:"candidate_fault,omitempty"`
	Manifests      map[string]Manifest    `json:"manifests"`
	Transfers      map[string]transferRef `json:"transfers"`
	Blobs          map[string]blobRecord  `json:"blobs"`
	Selected       *selectedRef           `json:"selected,omitempty"`
	Downloaded     string                 `json:"downloaded,omitempty"`
	Verified       *verifiedRef           `json:"verified,omitempty"`
	Staged         *stagedRef             `json:"staged,omitempty"`
	Lifecycle      *lifecycleRecord       `json:"lifecycle,omitempty"`
}

func stateDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func recordDigest(value any) (string, error) {
	raw, err := encodePrivateComponent(value)
	return stateDigest(raw), err
}
func validBlobID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

// Membership preserves the original artifact, independently of current policy.
func artifactIndex(manifest Manifest, artifact Artifact) (int, error) {
	for i, item := range manifest.Artifacts {
		if reflect.DeepEqual(item, artifact) {
			return i, nil
		}
	}
	return 0, ErrStorageUnavailable
}
func manifestShape(manifest Manifest) bool {
	return (manifest.SchemaVersion == 0 || manifest.SchemaVersion == schemaVersion) && validSafeName(manifest.AppID) &&
		validSafeName(string(manifest.Channel)) && validVersion(manifest.Version) && len(manifest.Artifacts) != 0
}
func artifactShape(a Artifact) bool {
	return a.Platform != "" && a.Architecture != "" && validArtifactFilename(a.Filename) && a.DownloadURL != "" && a.Size >= 0 && sha256Pattern.MatchString(a.SHA256)
}

func (r *stateRecord) addAuthority(m Manifest, a Artifact, source, policy string) (authorityRef, error) {
	if !manifestShape(m) || !artifactShape(a) {
		return authorityRef{}, ErrStorageUnavailable
	}
	index, err := artifactIndex(m, a)
	if err != nil {
		return authorityRef{}, err
	}
	id, err := recordDigest(m)
	if err != nil {
		return authorityRef{}, err
	}
	r.Manifests[id] = m
	return authorityRef{Manifest: id, Artifact: index, SourceKey: source, PolicyKey: policy}, nil
}
func (r *stateRecord) authority(ref authorityRef) (Manifest, Artifact, error) {
	m, ok := r.Manifests[ref.Manifest]
	if !ok || !manifestShape(m) || ref.Artifact < 0 || ref.Artifact >= len(m.Artifacts) {
		return Manifest{}, Artifact{}, ErrStorageUnavailable
	}
	a := m.Artifacts[ref.Artifact]
	if !artifactShape(a) {
		return Manifest{}, Artifact{}, ErrStorageUnavailable
	}
	return m, a, nil
}

func stagedArtifact(r stagedUpdateRecord) (Artifact, error) {
	if r.Manifest == nil || r.StagedAt.IsZero() || r.Size < 0 {
		return Artifact{}, ErrStorageUnavailable
	}
	m := *r.Manifest
	if r.AppID != m.AppID || r.Version != m.Version || r.Channel != m.Channel || r.RequiredRestart != m.RequiredRestart || r.ApplyBehavior != m.ApplyBehavior {
		return Artifact{}, ErrStorageUnavailable
	}
	for _, a := range m.Artifacts {
		if a.Platform == r.Platform && a.Architecture == r.Architecture && a.Filename == r.ArtifactName &&
			strings.EqualFold(a.SHA256, r.SHA256) && (a.Size == 0 || a.Size == r.Size) {
			return a, nil
		}
	}
	return Artifact{}, ErrStorageUnavailable
}

func (s *store) encodeState(v *stateView) ([]byte, error) {
	r := stateRecord{Version: 1, Manifests: map[string]Manifest{}, Transfers: map[string]transferRef{}, Blobs: map[string]blobRecord{}}
	addBlob := func(id, filename, role string, size int64) error {
		b, ok := v.blobs[id]
		if !ok || !validBlobID(id) || b.Filename != filename || b.Role != role || b.Size != size {
			return ErrStorageUnavailable
		}
		r.Blobs[id] = b
		return nil
	}
	addTransfer := func(d downloadedUpdate) (string, error) {
		if d.SchemaVersion != schemaVersion || d.DownloadedAt.IsZero() || d.BytesWritten < 0 {
			return "", ErrStorageUnavailable
		}
		ref, err := r.addAuthority(d.Manifest, d.Artifact, d.SourceKey, d.PolicyKey)
		if err != nil {
			return "", err
		}
		if err = addBlob(d.blobID, d.Artifact.Filename, "download", d.BytesWritten); err != nil {
			return "", err
		}
		if !samePath(d.ArtifactPath, s.blobPath(d.blobID, d.Artifact.Filename)) {
			return "", ErrStorageUnavailable
		}
		entry := transferRef{authorityRef: ref, Blob: d.blobID, BytesWritten: d.BytesWritten, DownloadedAt: d.DownloadedAt}
		id, err := recordDigest(entry)
		if err == nil {
			r.Transfers[id] = entry
		}
		return id, err
	}
	if v.candidateFault {
		if v.selected.value != nil || v.downloaded.value != nil || v.verified.value != nil {
			return nil, ErrStorageUnavailable
		}
		r.CandidateFault = candidateInvalid
	} else {
		if v.selected.err != nil || v.downloaded.err != nil || v.verified.err != nil {
			return nil, ErrStorageUnavailable
		}
		if item := v.selected.value; item != nil {
			if item.SchemaVersion != schemaVersion || item.UpdatedAt.IsZero() {
				return nil, ErrStorageUnavailable
			}
			ref, err := r.addAuthority(item.Manifest, item.Artifact, item.SourceKey, item.PolicyKey)
			if err != nil {
				return nil, err
			}
			r.Selected = &selectedRef{authorityRef: ref, UpdatedAt: item.UpdatedAt}
		}
		if v.downloaded.value != nil {
			id, err := addTransfer(*v.downloaded.value)
			if err != nil {
				return nil, err
			}
			r.Downloaded = id
		}
		if item := v.verified.value; item != nil {
			if item.SchemaVersion != schemaVersion || item.VerifiedAt.IsZero() {
				return nil, ErrStorageUnavailable
			}
			id, err := addTransfer(item.Downloaded)
			if err != nil {
				return nil, err
			}
			r.Verified = &verifiedRef{Transfer: id, VerifiedAt: item.VerifiedAt}
		}
	}
	if v.staged.err != nil || v.lifecycle.err != nil {
		return nil, ErrStorageUnavailable
	}
	if item := v.staged.value; item != nil {
		a, err := stagedArtifact(*item)
		if err != nil {
			return nil, err
		}
		ref, err := r.addAuthority(*item.Manifest, a, item.SourceKey, item.PolicyKey)
		if err != nil {
			return nil, err
		}
		if err = addBlob(item.blobID, item.ArtifactName, "staged", item.Size); err != nil {
			return nil, err
		}
		if !samePath(item.ArtifactPath, s.blobPath(item.blobID, item.ArtifactName)) {
			return nil, ErrStorageUnavailable
		}
		r.Staged = &stagedRef{authorityRef: ref, Source: item.Source, Blob: item.blobID, Size: item.Size, StagedAt: item.StagedAt}
		if item.SHA256 != a.SHA256 {
			r.Staged.SHA256 = item.SHA256
		}
	}
	if v.lifecycle.value != nil {
		if v.staged.value == nil || validateLifecycleRecord(*v.lifecycle.value, v.staged.value.StagedUpdate) != nil {
			return nil, ErrStorageUnavailable
		}
		r.Lifecycle = v.lifecycle.value
	}
	if len(r.Manifests) > 4 || len(r.Transfers) > 2 || len(r.Blobs) > 3 {
		return nil, ErrStorageUnavailable
	}
	return encodeStateRecord(r)
}

// Encode one manifest at a time, avoiding a second aggregate encoding of up to
// four legacy records. The JSON library still buffers each component internally;
// this is an encoded-byte limit, not a claim of streaming heap allocation.
func encodePrivateComponent(value any) ([]byte, error) {
	var buffer boundedStateBuffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func encodeStateRecord(r stateRecord) ([]byte, error) {
	var buffer boundedStateBuffer
	write := func(raw []byte) error { _, err := buffer.Write(raw); return err }
	if err := write([]byte(`{"manifests":{`)); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(r.Manifests))
	for id := range r.Manifests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i, id := range ids {
		if i > 0 {
			if err := write([]byte(",")); err != nil {
				return nil, err
			}
		}
		// IDs were calculated above and contain only lowercase hexadecimal.
		if err := write([]byte(`"` + id + `":`)); err != nil {
			return nil, err
		}
		raw, err := encodePrivateComponent(r.Manifests[id])
		if err != nil {
			return nil, err
		}
		if err := write(raw); err != nil {
			return nil, err
		}
	}
	if err := write([]byte("}")); err != nil {
		return nil, err
	}
	fields := []struct {
		name  string
		value any
		omit  bool
	}{
		{"version", r.Version, false}, {"candidate_fault", r.CandidateFault, r.CandidateFault == ""},
		{"transfers", r.Transfers, false}, {"blobs", r.Blobs, false},
		{"selected", r.Selected, r.Selected == nil}, {"downloaded", r.Downloaded, r.Downloaded == ""},
		{"verified", r.Verified, r.Verified == nil}, {"staged", r.Staged, r.Staged == nil},
		{"lifecycle", r.Lifecycle, r.Lifecycle == nil},
	}
	for _, field := range fields {
		if field.omit {
			continue
		}
		raw, err := encodePrivateComponent(field.value)
		if err != nil {
			return nil, err
		}
		if err := write([]byte(`,"` + field.name + `":`)); err != nil {
			return nil, err
		}
		if err := write(raw); err != nil {
			return nil, err
		}
	}
	if err := write([]byte("}")); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

type boundedStateBuffer struct{ bytes.Buffer }

func (b *boundedStateBuffer) Write(p []byte) (int, error) {
	if int64(b.Len())+int64(len(p)) > maxMetadataBytes {
		return 0, filepersist.ErrTooLarge
	}
	return b.Buffer.Write(p)
}

func (s *store) decodeState(raw []byte) (*stateView, error) {
	if err := validateNativeStateJSON(raw); err != nil {
		return nil, err
	}
	var r stateRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, ErrStorageUnavailable
	}
	if r.Version != 1 || r.Manifests == nil || r.Transfers == nil || r.Blobs == nil || len(r.Manifests) > 4 || len(r.Transfers) > 2 || len(r.Blobs) > 3 ||
		(r.CandidateFault != "" && r.CandidateFault != candidateInvalid) {
		return nil, ErrStorageUnavailable
	}
	for id, m := range r.Manifests {
		digest, err := recordDigest(m)
		if err != nil || digest != id || !manifestShape(m) {
			return nil, ErrStorageUnavailable
		}
	}
	for id, b := range r.Blobs {
		if !validBlobID(id) || !validArtifactFilename(b.Filename) || b.Size < 0 || !sha256Pattern.MatchString(b.SHA256) || (b.Role != "download" && b.Role != "staged") {
			return nil, ErrStorageUnavailable
		}
	}
	v := &stateView{blobs: r.Blobs}
	transfers := map[string]downloadedUpdate{}
	for id, entry := range r.Transfers {
		digest, err := recordDigest(entry)
		if err != nil || digest != id || entry.DownloadedAt.IsZero() {
			return nil, ErrStorageUnavailable
		}
		m, a, err := r.authority(entry.authorityRef)
		if err != nil {
			return nil, err
		}
		b, ok := r.Blobs[entry.Blob]
		if !ok || b.Role != "download" || b.Filename != a.Filename || b.Size != entry.BytesWritten {
			return nil, ErrStorageUnavailable
		}
		transfers[id] = downloadedUpdate{blobID: entry.Blob, SchemaVersion: schemaVersion, SourceKey: entry.SourceKey, PolicyKey: entry.PolicyKey,
			Manifest: m, Artifact: a, ArtifactPath: s.blobPath(entry.Blob, a.Filename), BytesWritten: entry.BytesWritten, DownloadedAt: entry.DownloadedAt}
	}
	if r.CandidateFault != "" {
		if r.Selected != nil || r.Downloaded != "" || r.Verified != nil || len(r.Transfers) != 0 {
			return nil, ErrStorageUnavailable
		}
		v.quarantineCandidate()
	} else {
		if item := r.Selected; item != nil {
			m, a, err := r.authority(item.authorityRef)
			if err != nil || item.UpdatedAt.IsZero() {
				return nil, ErrStorageUnavailable
			}
			v.selected = stored(selectedUpdate{SchemaVersion: schemaVersion, SourceKey: item.SourceKey, PolicyKey: item.PolicyKey, Manifest: m, Artifact: a, UpdatedAt: item.UpdatedAt})
		}
		if r.Downloaded != "" {
			item, ok := transfers[r.Downloaded]
			if !ok {
				return nil, ErrStorageUnavailable
			}
			v.downloaded = stored(item)
		}
		if r.Verified != nil {
			item, ok := transfers[r.Verified.Transfer]
			if !ok || r.Verified.VerifiedAt.IsZero() {
				return nil, ErrStorageUnavailable
			}
			v.verified = stored(verifiedUpdate{SchemaVersion: schemaVersion, Downloaded: item, VerifiedAt: r.Verified.VerifiedAt})
		}
	}
	if item := r.Staged; item != nil {
		m, a, err := r.authority(item.authorityRef)
		if err != nil || item.StagedAt.IsZero() {
			return nil, ErrStorageUnavailable
		}
		b, ok := r.Blobs[item.Blob]
		if !ok || b.Role != "staged" || b.Filename != a.Filename || b.Size != item.Size || (a.Size > 0 && item.Size != a.Size) {
			return nil, ErrStorageUnavailable
		}
		hash := a.SHA256
		if item.SHA256 != "" {
			if !strings.EqualFold(item.SHA256, a.SHA256) {
				return nil, ErrStorageUnavailable
			}
			hash = item.SHA256
		}
		v.staged = stored(stagedUpdateRecord{blobID: item.Blob, Manifest: &m, SourceKey: item.SourceKey, PolicyKey: item.PolicyKey,
			StagedUpdate: StagedUpdate{Source: item.Source, AppID: m.AppID, Version: m.Version, Channel: m.Channel, Platform: a.Platform,
				Architecture: a.Architecture, ArtifactName: a.Filename, ArtifactPath: s.blobPath(item.Blob, a.Filename), SHA256: hash,
				Size: item.Size, StagedAt: item.StagedAt, RequiredRestart: m.RequiredRestart, ApplyBehavior: m.ApplyBehavior}})
	}
	if r.Lifecycle != nil {
		if v.staged.value == nil || validateLifecycleRecord(*r.Lifecycle, v.staged.value.StagedUpdate) != nil {
			return nil, ErrStorageUnavailable
		}
		v.lifecycle = stored(*r.Lifecycle)
	}
	// Reject hidden unreferenced records as well as missing graph edges.
	encoded, err := s.encodeState(v)
	if err != nil {
		return nil, err
	}
	var reachable stateRecord
	if json.Unmarshal(encoded, &reachable) != nil || len(reachable.Manifests) != len(r.Manifests) || len(reachable.Transfers) != len(r.Transfers) || len(reachable.Blobs) != len(r.Blobs) {
		return nil, ErrStorageUnavailable
	}
	return v, nil
}

func (s *store) blobPath(id, filename string) string { return filepath.Join(s.blobDir(), id, filename) }

func (s *store) downloadedPathFor(d downloadedUpdate) string {
	if d.blobID != "" {
		return s.blobPath(d.blobID, d.Artifact.Filename)
	}
	return filepath.Join(s.downloadsDir(), d.Artifact.Filename)
}
func (s *store) stagedPathFor(r stagedUpdateRecord) string {
	if r.blobID != "" {
		return s.blobPath(r.blobID, r.ArtifactName)
	}
	return filepath.Join(s.stagedDir(), r.ArtifactName)
}

func structuralSelected(item selectedUpdate) bool {
	_, err := artifactIndex(item.Manifest, item.Artifact)
	return item.SchemaVersion == schemaVersion && !item.UpdatedAt.IsZero() && manifestShape(item.Manifest) && artifactShape(item.Artifact) && err == nil
}
func (s *store) structuralDownloaded(ctxPath string, d downloadedUpdate) error {
	_, err := artifactIndex(d.Manifest, d.Artifact)
	if d.SchemaVersion != schemaVersion || d.DownloadedAt.IsZero() || d.BytesWritten < 0 || !manifestShape(d.Manifest) || !artifactShape(d.Artifact) || err != nil ||
		!samePath(d.ArtifactPath, ctxPath) {
		return ErrStorageUnavailable
	}
	info, err := os.Lstat(ctxPath)
	if err != nil {
		return ErrVerificationFailed
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return filepersist.ErrUnsafePath
	}
	if info.Size() != d.BytesWritten || (d.Artifact.Size > 0 && info.Size() != d.Artifact.Size) {
		return ErrVerificationFailed
	}
	return nil
}
