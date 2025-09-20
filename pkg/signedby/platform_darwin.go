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

	output, stdout, err := runCodesign(ctx, path)
	if err != nil {
		return handleCodesignError(err, output, stdout, info, logger, path)
	}

	logger.Debug("codesign output received", "path", path, "outputLength", len(output))

	isPlatformBinary, authorities := parseCodesignOutput(output, info)

	setSignatureInfo(info, authorities, isPlatformBinary)
	applyAppleSpecificRules(info)

	if !opts.SkipValidation && info.SignatureValid != nil && *info.SignatureValid {
		performDeepValidation(ctx, path, info)
	}

	return info, nil
}

func runCodesign(ctx context.Context, path string) (stderr string, stdout string, err error) {
	cmd := exec.CommandContext(ctx, "codesign", "-dvvv", path)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	return stderrBuf.String(), stdoutBuf.String(), err
}

func handleCodesignError(err error, output, stdout string, info *SignatureInfo, logger *slog.Logger, path string) (*SignatureInfo, error) {
	outputLower := strings.ToLower(output)

	if strings.Contains(outputLower, "not signed") ||
		strings.Contains(outputLower, "unsigned") ||
		strings.Contains(outputLower, "ad-hoc") {
		return handleUnsignedBinary(output, info, logger, path)
	}

	if strings.Contains(outputLower, "not a mach-o file") ||
		strings.Contains(outputLower, "is not an app bundle") ||
		strings.Contains(outputLower, "a sealed resource is missing") {
		return handleVerificationIssue(output, info, logger, path)
	}

	return handleUnknownError(err, output, stdout, info, logger, path)
}

func handleUnsignedBinary(output string, info *SignatureInfo, logger *slog.Logger, path string) (*SignatureInfo, error) {
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

func handleVerificationIssue(output string, info *SignatureInfo, logger *slog.Logger, path string) (*SignatureInfo, error) {
	logger.Debug("binary cannot be verified", "path", path, "reason", output)
	info.SignatureValid = boolPtr(false)
	info.Extra["verifyError"] = strings.TrimSpace(output)
	return info, nil
}

func handleUnknownError(err error, output, stdout string, info *SignatureInfo, logger *slog.Logger, path string) (*SignatureInfo, error) {
	trimmedOutput := strings.TrimSpace(output)
	if trimmedOutput == "" {
		trimmedOutput = "(no output from codesign)"
	}
	logger.Error("codesign failed",
		"path", path,
		"error", err,
		"stderr", trimmedOutput,
		"stdout", strings.TrimSpace(stdout))
	info.SignatureValid = boolPtr(false)
	info.Extra["codesignError"] = err.Error()
	if trimmedOutput != "" && len(trimmedOutput) < 500 {
		info.Extra["details"] = trimmedOutput
	}
	return info, nil
}

func parseCodesignOutput(output string, info *SignatureInfo) (isPlatformBinary bool, authorities []string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Platform Binary=") && strings.Contains(line, "=Yes") {
			isPlatformBinary = true
			info.IsPlatform = true
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
			if info.PackageName == "" {
				info.PackageName = identifier
			}
		}

		if strings.HasPrefix(line, "Info.plist entries=") {
			entries := strings.TrimPrefix(line, "Info.plist entries=")
			info.Extra["infoPlistEntries"] = entries
		}
	}

	return isPlatformBinary, authorities
}

func setSignatureInfo(info *SignatureInfo, authorities []string, isPlatformBinary bool) {
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
}

func applyAppleSpecificRules(info *SignatureInfo) {
	if identifier, ok := info.Extra["identifier"].(string); ok {
		if strings.HasPrefix(identifier, "com.apple.") {
			info.IsPlatform = true
			if info.SignerOrg == "" {
				info.SignerOrg = "Apple"
			}
		}
	}
}

func performDeepValidation(ctx context.Context, path string, info *SignatureInfo) {
	validateCmd := exec.CommandContext(ctx, "codesign", "--verify", "--deep", "--strict", path)
	if err := validateCmd.Run(); err != nil {
		info.SignatureValid = boolPtr(false)
		info.Extra["validationError"] = err.Error()
	}
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
