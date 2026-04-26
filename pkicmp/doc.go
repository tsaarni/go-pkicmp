// Package pkicmp provides types for handling Certificate Management Protocol (CMP)
// messages as defined in RFC 9810.
//
// # How it works
//
// This package is built around the [PKIMessage] struct. While most structs in
// the package (like [PKIHeader] and [PKIBody]) are public so you can easily
// read or set their fields, only the top-level [PKIMessage] provides the
// standard Go [encoding.BinaryMarshaler] and [encoding.BinaryUnmarshaler]
// interfaces.
//
// ## Standard Go Interfaces
//
// Use [PKIMessage.MarshalBinary] and [ParsePKIMessage] (which wraps UnmarshalBinary)
// to convert between Go structs and raw DER bytes. These methods make the
// package compatible with standard Go tools like [http.Client].
//
// ## Internal Encoding Logic
//
// Components within the package use the cryptobyte library to process DER data
// as a stream. This approach is used for two practical reasons:
//
//  1. ASN.1 Nesting: In DER encoding, a "parent" (like a SEQUENCE) must know
//     the total size of its "children" before it can write its own length.
//     Marshaling is handled by passing a *cryptobyte.Builder to each component,
//     allowing them to append directly to a single shared buffer while the
//     library handles nested length calculations automatically.
//  2. Performance and Memory: Parsing is handled by passing a *cryptobyte.String.
//     This provides each component with a zero-copy "view" of the original
//     buffer, ensuring that no data is copied as the message is decoded into
//     the struct hierarchy.
//
// All internal types that participate in message encoding implement an interface
// for recursive marshaling and unmarshaling:
//
//	type marshaler interface {
//	    marshal(mctx *MarshalContext, b *cryptobyte.Builder)
//	    unmarshal(s *cryptobyte.String) error
//	}
//
// ## Thread Safety
//
// Types in this package (including PKIMessage and PKIBody) are not thread-safe.
// Concurrent access to a message or any of its components must be synchronized
// by the caller.
//
// ## Usage Example
//
// Sending and receiving CMP messages using the standard Go HTTP client:
//
//	// 1. Create and marshal a message
//	msg := &pkicmp.PKIMessage{
//	    Header: pkicmp.PKIHeader{ ... },
//	    Body:   pkicmp.NewPKIConfBody(),
//	}
//	der, _ := msg.MarshalBinary()
//
//	// 2. Send via HTTP
//	resp, _ := http.Post("https://ca.example.com/pkix/", "application/pkixcmp", bytes.NewReader(der))
//	defer resp.Body.Close()
//
//	// 3. Parse the response
//	body, _ := io.ReadAll(resp.Body)
//	parsed, _ := pkicmp.ParsePKIMessage(body)
package pkicmp
