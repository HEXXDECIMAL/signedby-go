//go:build linux

package signedby

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// Package manager related constants
const (
	archLinuxDomain = "archlinux.org"
	signatureKeyword = "Signature"
	ownedByMarker = "is owned by"
	validatedByMarker = "Validated By"
	packagerField = "Packager"
	vendorField = "Vendor"
)

func verifyLinux(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	distro := detectLinuxDistro()
	opts.Logger.Debug("detected Linux distro", "distro", distro)

	switch distro {
	case "rpm":
		return verifyRPM(ctx, path, opts)
	case "deb":
		return verifyDEB(ctx, path, opts)
	case "alpine":
		return verifyAPK(ctx, path, opts)
	case "arch":
		return verifyArch(ctx, path, opts)
	default:
		opts.Logger.Debug("unknown Linux distro, cannot verify", "distro", distro)
		return &SignatureInfo{
			Path:  path,
			Extra: map[string]any{"distro": "unknown"},
		}, nil
	}
}

func detectLinuxDistro() string {
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "rpm"
	}
	if _, err := os.Stat("/etc/SuSE-release"); err == nil {
		return "rpm"
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		return "rpm"
	}

	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "deb"
	}
	if _, err := exec.LookPath("dpkg"); err == nil {
		return "deb"
	}

	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		return "alpine"
	}
	if _, err := exec.LookPath("apk"); err == nil {
		return "alpine"
	}

	if _, err := os.Stat("/etc/arch-release"); err == nil {
		return "arch"
	}
	if _, err := exec.LookPath("pacman"); err == nil {
		return "arch"
	}

	return "unknown"
}

func verifyRPM(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	info := &SignatureInfo{
		Path:          path,
		SigningMethod: "rpm",
		Extra:         make(map[string]any),
	}

	cmd := exec.CommandContext(ctx, "rpm", "-qf", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		info.IsPackaged = false
		return info, nil
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" {
		info.IsPackaged = false
		return info, nil
	}

	info.IsPackaged = true

	opts.Logger.Debug("rpm -qf output", "path", path, "output", output)

	// Handle multiple packages (when file belongs to multiple versions)
	// rpm -qf lists packages with most recent last, so we'll use the last one
	packages := strings.Split(output, "\n")

	// Filter out empty strings
	var validPackages []string
	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg != "" {
			validPackages = append(validPackages, pkg)
		}
	}

	// Use the last (most recent) package
	var packageName string
	if len(validPackages) > 0 {
		packageName = validPackages[len(validPackages)-1]
		opts.Logger.Debug("selected package", "packageName", packageName, "totalPackages", len(validPackages))
		// Store all packages in Extra for reference
		if len(validPackages) > 1 {
			info.Extra["allPackages"] = validPackages
		}
	} else {
		// Shouldn't happen, but handle gracefully
		info.IsPackaged = false
		return info, nil
	}

	// Get just the package name
	// packageName is like "bash-5.2.37-1.fc42.aarch64", we can query it directly
	cmd = exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{NAME}", packageName)
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		name := strings.TrimSpace(stdout.String())
		opts.Logger.Debug("rpm query result", "packageName", packageName, "name", name)
		if name != "" {
			info.PackageName = name
		} else {
			// Fallback: extract name from package string (e.g., "bash" from "bash-5.2.37-1.fc42.aarch64")
			parts := strings.Split(packageName, "-")
			if len(parts) > 0 {
				info.PackageName = parts[0]
			}
		}
	} else {
		opts.Logger.Debug("rpm query failed", "packageName", packageName, "err", err)
		// If rpm query fails, try to extract the package name from the full string
		// Package format is typically: name-version-release.arch
		parts := strings.Split(packageName, "-")
		if len(parts) > 0 {
			info.PackageName = parts[0]
		} else {
			info.PackageName = packageName
		}
	}

	// Get the version
	cmd = exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", packageName)
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		version := strings.TrimSpace(stdout.String())
		if version != "" {
			info.PackageVersion = version
		}
	} else {
		// Try to extract version from package string
		parts := strings.Split(packageName, "-")
		if len(parts) >= 3 {
			// Remove arch suffix if present
			lastPart := parts[len(parts)-1]
			if strings.Contains(lastPart, ".") && (strings.HasSuffix(lastPart, "64") || strings.HasSuffix(lastPart, "86")) {
				lastPart = strings.Split(lastPart, ".")[0]
				parts[len(parts)-1] = lastPart
			}
			info.PackageVersion = strings.Join(parts[1:], "-")
		}
	}

	// Get vendor information - parse from rpm -qi output as queryformat might not work
	cmd = exec.CommandContext(ctx, "rpm", "-qi", packageName)
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		output := stdout.String()
		for _, line := range strings.Split(output, "\n") {
			// Parse Vendor field
			if strings.HasPrefix(line, vendorField) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					vendor := strings.TrimSpace(parts[1])
					if vendor != "" && vendor != "(none)" {
						info.SignerOrg = vendor
						if isOSVendor(vendor) {
							info.IsPlatform = true
						}
					}
				}
			}
			// Parse Signature field for signature verification
			if strings.HasPrefix(line, signatureKeyword) {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					sig := strings.TrimSpace(parts[1])
					// Fedora format: "RSA/SHA256, <date>, Key ID <keyid>"
					if sig != "" && sig != "(none)" {
						info.SignatureValid = boolPtr(true)
						info.Extra["signature"] = sig
						// Extract key ID if present
						if idx := strings.Index(sig, "Key ID "); idx != -1 {
							keyID := sig[idx+7:]
							info.Extra["keyID"] = keyID
						}
					} else {
						info.SignatureValid = boolPtr(false)
					}
				}
			}
		}
	}

	// Additional signature verification if needed and not already found
	if !opts.SkipValidation && info.SignatureValid == nil {
		// Try to get signature info using queryformat as fallback
		cmd = exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{DSAHEADER:pgpsig}%{RSAHEADER:pgpsig}%{SIGGPG:pgpsig}%{SIGPGP:pgpsig}\n", packageName)
		stdout.Reset()
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			output := strings.TrimSpace(stdout.String())
			// Check if any signature field has content
			if output != "" && output != "(none)(none)(none)(none)" && !strings.Contains(output, "(none)") {
				info.SignatureValid = boolPtr(true)
				info.Extra["pgpSignatures"] = output
			}
		}

		// If we still don't have signature info, check package integrity
		if info.SignatureValid == nil {
			// Check if the RPM database shows the package as intact
			cmd = exec.CommandContext(ctx, "rpm", "-V", packageName)
			if err := cmd.Run(); err == nil {
				// If rpm -V succeeds without errors, package integrity is good
				// This means the package was installed from a repository
				info.SignatureValid = boolPtr(true)
				info.Extra["integrityVerified"] = true
			}
		}
	}

	opts.Logger.Debug("final RPM info", "packageName", info.PackageName, "version", info.PackageVersion, "vendor", info.SignerOrg)
	return info, nil
}

func verifyDEB(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	info := &SignatureInfo{
		Path:          path,
		SigningMethod: "dpkg",
		Extra:         make(map[string]any),
	}

	opts.Logger.Debug("verifying DEB package", "path", path)

	cmd := exec.CommandContext(ctx, "dpkg", "-S", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		opts.Logger.Debug("dpkg -S failed", "path", path, "error", err, "stderr", stderr.String())
		if strings.Contains(stderr.String(), "not found") {
			opts.Logger.Warn("binary not found in any package", "path", path)
		}
		info.IsPackaged = false
		return info, nil
	}

	output := strings.TrimSpace(stdout.String())
	opts.Logger.Debug("dpkg -S output", "path", path, "output", output)

	if output == "" {
		opts.Logger.Debug("dpkg -S returned empty output", "path", path)
		info.IsPackaged = false
		return info, nil
	}

	parts := strings.Split(output, ":")
	if len(parts) > 0 {
		info.PackageName = strings.TrimSpace(parts[0])
		info.IsPackaged = true
		opts.Logger.Debug("found package", "packageName", info.PackageName)
	}

	if info.PackageName != "" {
		cmd = exec.CommandContext(ctx, "dpkg", "-s", info.PackageName)
		stdout.Reset()
		stderr.Reset()
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			output := stdout.String()
			opts.Logger.Debug("dpkg -s output received", "packageName", info.PackageName, "outputLength", len(output))

			for _, line := range strings.Split(output, "\n") {
				if strings.HasPrefix(line, "Version:") {
					info.PackageVersion = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
					opts.Logger.Debug("found version", "version", info.PackageVersion)
				}
				if strings.HasPrefix(line, "Maintainer:") {
					maintainer := strings.TrimSpace(strings.TrimPrefix(line, "Maintainer:"))
					opts.Logger.Debug("found maintainer", "maintainer", maintainer)
					if strings.Contains(maintainer, "Ubuntu") {
						info.SignerOrg = "Ubuntu"
						info.IsPlatform = true
						opts.Logger.Debug("detected Ubuntu package")
					} else if strings.Contains(maintainer, "Debian") {
						info.SignerOrg = "Debian"
						info.IsPlatform = true
						opts.Logger.Debug("detected Debian package")
					} else {
						info.Extra["maintainer"] = maintainer
					}
				}
				if strings.HasPrefix(line, "Origin:") {
					origin := strings.TrimSpace(strings.TrimPrefix(line, "Origin:"))
					opts.Logger.Debug("found origin", "origin", origin)
					info.SignerOrg = origin
					if isOSVendor(origin) {
						info.IsPlatform = true
						opts.Logger.Debug("detected platform vendor", "vendor", origin)
					}
				}
			}
		} else {
			opts.Logger.Debug("dpkg -s failed", "packageName", info.PackageName, "error", err, "stderr", stderr.String())
		}
	}

	aptListsDir := "/var/lib/apt/lists"
	if files, err := os.ReadDir(aptListsDir); err == nil && len(files) > 0 {
		info.SignatureValid = boolPtr(true)
		info.Extra["repoSigned"] = true
		opts.Logger.Debug("APT lists found, marking as signed", "fileCount", len(files))
	} else {
		opts.Logger.Debug("APT lists check", "error", err, "fileCount", 0)
	}

	return info, nil
}

func verifyAPK(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	info := &SignatureInfo{
		Path:          path,
		SigningMethod: "apk",
		Extra:         make(map[string]any),
	}

	cmd := exec.CommandContext(ctx, "apk", "info", "--who-owns", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		info.IsPackaged = false
		return info, nil
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" || strings.Contains(output, "ERROR") {
		info.IsPackaged = false
		return info, nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, ownedByMarker) {
			parts := strings.Split(line, ownedByMarker)
			if len(parts) > 1 {
				pkgInfo := strings.TrimSpace(parts[1])
				pkgParts := strings.Split(pkgInfo, "-")
				if len(pkgParts) >= 2 {
					info.PackageName = strings.Join(pkgParts[:len(pkgParts)-2], "-")
					info.PackageVersion = strings.Join(pkgParts[len(pkgParts)-2:], "-")
				} else {
					info.PackageName = pkgInfo
				}
				info.IsPackaged = true
				break
			}
		}
	}

	if info.PackageName != "" {
		cmd = exec.CommandContext(ctx, "apk", "info", "-d", info.PackageName)
		stdout.Reset()
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			output := stdout.String()
			if strings.Contains(output, "Alpine") {
				info.SignerOrg = "Alpine Linux"
				info.IsPlatform = true
			}
		}
	}

	if _, err := os.Stat("/etc/apk/keys"); err == nil {
		info.SignatureValid = boolPtr(true)
		info.Extra["keysPresent"] = true
	}

	return info, nil
}

func verifyArch(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	info := &SignatureInfo{
		Path:          path,
		SigningMethod: "pacman",
		Extra:         make(map[string]any),
	}

	cmd := exec.CommandContext(ctx, "pacman", "-Qo", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		info.IsPackaged = false
		return info, nil
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" {
		info.IsPackaged = false
		return info, nil
	}

	parts := strings.Split(output, "is owned by")
	if len(parts) > 1 {
		pkgInfo := strings.TrimSpace(parts[1])
		pkgParts := strings.Fields(pkgInfo)
		if len(pkgParts) >= 2 {
			info.PackageName = pkgParts[0]
			info.PackageVersion = pkgParts[1]
		} else if len(pkgParts) == 1 {
			info.PackageName = pkgParts[0]
		}
		info.IsPackaged = true
	}

	if info.PackageName != "" {
		cmd = exec.CommandContext(ctx, "pacman", "-Qi", info.PackageName)
		stdout.Reset()
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			output := stdout.String()
			for _, line := range strings.Split(output, "\n") {
				if strings.HasPrefix(line, packagerField) {
					packager := strings.TrimSpace(strings.TrimPrefix(line, packagerField))
					packager = strings.TrimPrefix(packager, ":")
					packager = strings.TrimSpace(packager)
					if strings.Contains(packager, archLinuxDomain) {
						info.SignerOrg = "Arch Linux"
						info.IsPlatform = true
					} else {
						info.Extra["packager"] = packager
					}
				}
				if strings.HasPrefix(line, validatedByMarker) {
					validated := strings.TrimSpace(strings.TrimPrefix(line, validatedByMarker))
					validated = strings.TrimPrefix(validated, ":")
					validated = strings.TrimSpace(validated)
					if strings.Contains(validated, signatureKeyword) {
						info.SignatureValid = boolPtr(true)
					} else {
						info.SignatureValid = boolPtr(false)
					}
					info.Extra["validatedBy"] = validated
				}
			}
		}
	}

	return info, nil
}

// Pre-computed lowercase OS vendor names for efficiency
var osVendorsLower = []string{
	"red hat", "redhat", "fedora", "centos", "rocky", "almalinux",
	"ubuntu", "debian", "canonical",
	"suse", "opensuse", "alpine", "arch linux",
}

func isOSVendor(vendor string) bool {
	vendorLower := strings.ToLower(vendor)
	return slices.ContainsFunc(osVendorsLower, func(v string) bool {
		return strings.Contains(vendorLower, v)
	})
}
