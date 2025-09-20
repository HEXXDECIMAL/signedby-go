//go:build !darwin && !linux && !freebsd && windows

package signedby

import "context"

func verifyDarwin(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	return &SignatureInfo{
		Path:  path,
		Extra: map[string]any{"error": "darwin not supported on this platform"},
	}, nil
}

func verifyLinux(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	return &SignatureInfo{
		Path:  path,
		Extra: map[string]any{"error": "linux not supported on this platform"},
	}, nil
}

func verifyFreeBSD(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	return &SignatureInfo{
		Path:  path,
		Extra: map[string]any{"error": "freebsd not supported on this platform"},
	}, nil
}
