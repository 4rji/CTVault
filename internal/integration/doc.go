// Package integration holds the real-data tests (build tag realdata). They
// read the samples cached by "ctvault-dev sample capture" over loopback and
// never touch the network; without a cached sample they skip.
//
//	go test -race -tags realdata ./internal/integration/
package integration
