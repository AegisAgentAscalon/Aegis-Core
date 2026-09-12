package profilesync

import (
	"slices"
	"sort"
)

// inboxView belongs to one pending pass and one expected inbox revision. It is
// never shared with providers; a failed compare-and-swap discards the view.
type inboxView struct {
	state             inboxState
	positions         map[string]int
	snapshotDigests   map[string]string
	proposalDigests   map[string]string
	proposals         []RemoteProposalRecord
	proposalPositions []int
}

func newInboxView(state inboxState) inboxView {
	v := inboxView{state: state, positions: make(map[string]int, len(state.Entries)), snapshotDigests: map[string]string{}, proposalDigests: map[string]string{}}
	for index, entry := range state.Entries {
		v.positions[entry.ReceiptID] = index
		v.addDomain(index, entry)
	}
	return v
}

func (v *inboxView) addDomain(index int, entry inboxEntry) {
	if entry.Snapshot != nil {
		v.snapshotDigests[entry.Snapshot.Snapshot.Metadata.SnapshotID] = entry.DomainDigest
	}
	if entry.Proposal != nil {
		v.proposalDigests[entry.Proposal.Proposal.ProposalID] = entry.DomainDigest
		at := sort.SearchInts(v.proposalPositions, index)
		v.proposalPositions = slices.Insert(v.proposalPositions, at, index)
		v.proposals = slices.Insert(v.proposals, at, *entry.Proposal)
	}
}

func (v *inboxView) accepted(entry inboxEntry) {
	index := v.positions[entry.ReceiptID]
	v.state.Entries[index] = entry
	v.state.Revision++
	v.addDomain(index, entry)
}
