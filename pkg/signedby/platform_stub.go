//go:build !darwin && !linux && !windows && !freebsd

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

func verifyWindows(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	return &SignatureInfo{
		Path:  path,
		Extra: map[string]any{"error": "windows not supported on this platform"},
	}, nil
}

func verifyFreeBSD(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	return &SignatureInfo{
		Path:  path,
		Extra: map[string]any{"error": "freebsd not supported on this platform"},
	}, nil
}
