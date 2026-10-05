//go:build !nightly

package commit_test

// killLoopRuns is the random kill loop's length in the normal suite
// (amendment A1 §9); -tags nightly runs 200.
const killLoopRuns = 25
