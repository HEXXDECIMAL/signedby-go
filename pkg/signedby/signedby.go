// Package signedby provides functionality to identify binary origins and signatures.
package signedby

import (
	"log/slog"
	"os"
	"time"
)

// SignatureInfo contains information about a binary's origin and signature.
//
//nolint:govet // field alignment micro-optimization not needed
type SignatureInfo struct {
	Path           string
	PackageName    string
	PackageVersion string
	SignerOrg      string
	SigningMethod  string
	Extra          map[string]any
	SignatureValid *bool
	IsPackaged     bool
	IsPlatform     bool
}

// Verifier is the interface for verifying binary signatures.
type Verifier interface {
	Verify(path string) (*SignatureInfo, error)
	VerifyWithOptions(path string, opts VerifyOptions) (*SignatureInfo, error)
}

// VerifyOptions contains options for verification.
type VerifyOptions struct {
	Logger         *slog.Logger
	Timeout        time.Duration
	UseCache       bool
	SkipValidation bool
}

// New creates a new verifier without caching.
func New() Verifier {
	return &verifier{
		cache:  nil,
		logger: defaultLogger(),
	}
}

// NewWithCache creates a new verifier with caching enabled.
func NewWithCache() Verifier {
	return &verifier{
		cache:  newCache(),
		logger: defaultLogger(),
	}
}

// NewWithLogger creates a new verifier with a custom logger.
func NewWithLogger(logger *slog.Logger, useCache bool) Verifier {
	v := &verifier{
		logger: logger,
	}
	if useCache {
		v.cache = newCache()
	}
	return v
}

// defaultLogger creates a logger that only shows errors to stderr.
func defaultLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

// boolPtr returns a pointer to the given boolean value.
func boolPtr(b bool) *bool {
	return &b
}
