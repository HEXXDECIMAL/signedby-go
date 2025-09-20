//go:build darwin

package signedby

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"strings"
)

func verifyDarwin(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	logger.Debug("verifying macOS binary", "path", path)

	info := &SignatureInfo{
		Path:          path,
		SigningMethod: "codesign",
		Extra:         make(map[string]any),
	}

	cmd := exec.CommandContext(ctx, "codesign", "-dvvv", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stderr.String()

	if err != nil {
		// Check various unsigned states
		outputLower := strings.ToLower(output)
		if strings.Contains(outputLower, "not signed") ||
			strings.Contains(outputLower, "unsigned") ||
			strings.Contains(outputLower, "ad-hoc") {
			logger.Debug("binary is not signed or ad-hoc signed", "path", path)
			info.SignatureValid = boolPtr(false)
			// Extract any partial info we can from the output
			if strings.Contains(output, "Identifier=") {
				for _, line := range strings.Split(output, "\n") {
					if strings.HasPrefix(line, "Identifier=") {
						info.PackageName = strings.TrimPrefix(line, "Identifier=")
						break
					}
				}
			}
			return info, nil
		}

		// Check for other known issues
		if strings.Contains(outputLower, "not a mach-o file") ||
		   strings.Contains(outputLower, "is not an app bundle") ||
		   strings.Contains(outputLower, "a sealed resource is missing") {
			logger.Debug("binary cannot be verified", "path", path, "reason", output)
			info.SignatureValid = boolPtr(false)
			info.Extra["verifyError"] = strings.TrimSpace(output)
			return info, nil
		}

		// Unknown error - log full details to help debug
		trimmedOutput := strings.TrimSpace(output)
		if trimmedOutput == "" {
			trimmedOutput = "(no output from codesign)"
		}
		logger.Error("codesign failed",
			"path", path,
			"error", err,
			"stderr", trimmedOutput,
			"stdout", strings.TrimSpace(stdout.String()))
		info.SignatureValid = boolPtr(false)
		info.Extra["codesignError"] = err.Error()
		if len(trimmedOutput) > 0 && len(trimmedOutput) < 500 {
			info.Extra["details"] = trimmedOutput
		}
		return info, nil
	}

	logger.Debug("codesign output received", "path", path, "outputLength", len(output))

	isPlatformBinary := false
	var authorities []string

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Platform Binary=") {
			if strings.Contains(line, "=Yes") {
				isPlatformBinary = true
				info.IsPlatform = true
			}
		}

		if strings.HasPrefix(line, "Authority=") {
			auth := strings.TrimPrefix(line, "Authority=")
			authorities = append(authorities, auth)
		}

		if strings.HasPrefix(line, "TeamIdentifier=") {
			teamID := strings.TrimPrefix(line, "TeamIdentifier=")
			info.Extra["teamIdentifier"] = teamID
		}

		if strings.HasPrefix(line, "Identifier=") {
			identifier := strings.TrimPrefix(line, "Identifier=")
			info.Extra["identifier"] = identifier
			// Use identifier as package name for macOS
			if info.PackageName == "" {
				info.PackageName = identifier
			}
		}

		if strings.HasPrefix(line, "Info.plist entries=") {
			entries := strings.TrimPrefix(line, "Info.plist entries=")
			info.Extra["infoPlistEntries"] = entries
		}
	}

	if len(authorities) > 0 {
		info.SignerOrg = extractOrgFromAuthority(authorities[0])
		info.Extra["authorities"] = authorities
		info.SignatureValid = boolPtr(true)
	} else {
		info.SignatureValid = boolPtr(false)
	}

	if isPlatformBinary && info.SignerOrg == "" {
		info.SignerOrg = "Apple"
	}

	if identifier, ok := info.Extra["identifier"].(string); ok {
		if strings.HasPrefix(identifier, "com.apple.") {
			info.IsPlatform = true
			if info.SignerOrg == "" {
				info.SignerOrg = "Apple"
			}
		}
	}

	if !opts.SkipValidation && info.SignatureValid != nil && *info.SignatureValid {
		validateCmd := exec.CommandContext(ctx, "codesign", "--verify", "--deep", "--strict", path)
		if err := validateCmd.Run(); err != nil {
			info.SignatureValid = boolPtr(false)
			info.Extra["validationError"] = err.Error()
		}
	}

	return info, nil
}

func extractOrgFromAuthority(authority string) string {
	if strings.Contains(authority, "Apple") {
		return "Apple"
	}

	parts := strings.Split(authority, ":")
	if len(parts) > 1 {
		orgPart := parts[len(parts)-1]
		if strings.HasPrefix(orgPart, " ") {
			orgPart = strings.TrimSpace(orgPart)
		}
		orgPart = strings.TrimSuffix(orgPart, ")")
		orgPart = strings.TrimPrefix(orgPart, "(")
		return orgPart
	}

	if strings.Contains(authority, "Developer ID") {
		start := strings.Index(authority, "Developer ID")
		if start != -1 {
			substr := authority[start:]
			if idx := strings.Index(substr, ":"); idx != -1 {
				return strings.TrimSpace(substr[idx+1:])
			}
		}
	}

	return authority
}

func boolPtr(b bool) *bool {
	return &b
}
