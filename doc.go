// Package tunnel provides QUIC-backed raw net.Listeners for Go servers.
//
// Dial requires an existing identity approved by the server. ListenRaw returns
// unmodified public bytes; the application owns TLS. Storage and persisted
// Ed25519 credentials and signed RequestJoin bootstrap are included. Listen
// performs local ACME TLS; ListenTLS uses application-provided certificates.
// ListenHTTP opts into one-shot plain HTTP. EnsureJoined and
// EnsureJoinedAndListen support a join-then-wait workflow for administrator
// approval, with optional event callbacks. Clients reconnect automatically
// without replaying in-flight requests. CloseGracefully unadvertises and drains
// allocated streams within a caller-supplied context.
package tunnel
