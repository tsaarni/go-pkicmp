// Package server implements a CMP protocol handler that can be embedded in a
// CA or RA server to add CMP support. It handles all protocol mechanics —
// HTTP transport, message parsing, protection verification, response
// construction, nonce/transaction management, and the certConf round-trip.
//
// The user implements a [Handler] interface that makes CA decisions.
//
// # HTTP Transport
//
// The [Server] type implements [net/http.Handler] per RFC 6712 §3.
//
// # Example
//
//	s := server.New(myHandler,
//	    server.WithSigner(caKey, caCert),
//	)
//	http.ListenAndServe(":8080", s)
package server
