package identitygate

// ScopeAccessDecision explains a scope check without exposing provider internals.
type ScopeAccessDecision struct {
	Scope             Scope
	Allowed           bool
	KnownScope        bool
	ReauthRequired    bool
	FreshRequired     bool
	Locked            bool
	CurrentAssurance  AssuranceLevel
	OperatorAssurance OperatorAssurance
	Reason            string
}
