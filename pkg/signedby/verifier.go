package signedby

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"
)

type verifier struct {
	cache  *cache
	logger *slog.Logger
}

func (v *verifier) Verify(path string) (*SignatureInfo, error) {
	return v.VerifyWithOptions(path, VerifyOptions{
		UseCache: v.cache != nil,
		Timeout:  30 * time.Second,
	})
}

func (v *verifier) VerifyWithOptions(path string, opts VerifyOptions) (*SignatureInfo, error) {
	logger := v.logger
	if opts.Logger != nil {
		logger = opts.Logger
	}

	logger.Debug("verifying binary", "path", path)

	if _, err := os.Stat(path); err != nil {
		logger.Debug("file not found", "path", path, "error", err)
		return nil, fmt.Errorf("file not found: %w", err)
	}

	if opts.UseCache && v.cache != nil {
		if cached, ok := v.cache.get(path); ok {
			logger.Debug("returning cached result", "path", path)
			return cached, nil
		}
		logger.Debug("cache miss", "path", path)
	}

	ctx := context.Background()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	var info *SignatureInfo
	var err error

	logger.Debug("detecting platform", "os", runtime.GOOS)

	switch runtime.GOOS {
	case "darwin":
		info, err = verifyDarwin(ctx, path, opts)
	case "linux":
		info, err = verifyLinux(ctx, path, opts)
	case "windows":
		info, err = verifyWindows(ctx, path, opts)
	case "freebsd":
		info, err = verifyFreeBSD(ctx, path, opts)
	default:
		return &SignatureInfo{
			Path:  path,
			Extra: map[string]any{"error": "unsupported platform"},
		}, nil
	}

	if err != nil {
		logger.Error("verification error", "path", path, "error", err)
		// Don't cache errors - they might be transient
		return &SignatureInfo{
			Path:  path,
			Extra: map[string]any{"error": err.Error()},
		}, nil
	}

	// Only cache successful results or results with error info in Extra
	if opts.UseCache && v.cache != nil && info != nil {
		// Don't cache if there's an error in the Extra field
		if errVal, hasError := info.Extra["error"]; !hasError || errVal == nil {
			logger.Debug("caching result", "path", path)
			v.cache.set(path, info)
		} else {
			logger.Debug("not caching error result", "path", path, "error", errVal)
		}
	}

	return info, nil
}
