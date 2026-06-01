// Package relay is reserved for private relay/rendezvous implementation helpers.
//
// Pass 2C keeps the public relay contracts standalone in pkg/relay so the
// public package does not import internal implementation packages or other
// domain internals. Future private helpers may live here if they do not become
// trust, profile, sync, routing, or production relay authorities.
package relay
