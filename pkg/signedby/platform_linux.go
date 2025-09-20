//go:build linux

package signedby

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
)

func verifyLinux(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	distro := detectLinuxDistro()

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
	cmd = exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{NAME}", packageName)
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		name := strings.TrimSpace(stdout.String())
		if name != "" {
			info.PackageName = name
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
	}

	// Get vendor information - parse from rpm -qi output as queryformat might not work
	cmd = exec.CommandContext(ctx, "rpm", "-qi", packageName)
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		output := stdout.String()
		for _, line := range strings.Split(output, "\n") {
			// Parse Vendor field
			if strings.HasPrefix(line, "Vendor") {
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
			if strings.HasPrefix(line, "Signature") {
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

	return info, nil
}

func verifyDEB(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	info := &SignatureInfo{
		Path:          path,
		SigningMethod: "dpkg",
		Extra:         make(map[string]any),
	}

	cmd := exec.CommandContext(ctx, "dpkg", "-S", path)
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

	parts := strings.Split(output, ":")
	if len(parts) > 0 {
		info.PackageName = strings.TrimSpace(parts[0])
		info.IsPackaged = true
	}

	if info.PackageName != "" {
		cmd = exec.CommandContext(ctx, "dpkg", "-s", info.PackageName)
		stdout.Reset()
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			output := stdout.String()
			for _, line := range strings.Split(output, "\n") {
				if strings.HasPrefix(line, "Version:") {
					info.PackageVersion = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
				}
				if strings.HasPrefix(line, "Maintainer:") {
					maintainer := strings.TrimSpace(strings.TrimPrefix(line, "Maintainer:"))
					if strings.Contains(maintainer, "Ubuntu") {
						info.SignerOrg = "Ubuntu"
						info.IsPlatform = true
					} else if strings.Contains(maintainer, "Debian") {
						info.SignerOrg = "Debian"
						info.IsPlatform = true
					} else {
						info.Extra["maintainer"] = maintainer
					}
				}
				if strings.HasPrefix(line, "Origin:") {
					origin := strings.TrimSpace(strings.TrimPrefix(line, "Origin:"))
					info.SignerOrg = origin
					if isOSVendor(origin) {
						info.IsPlatform = true
					}
				}
			}
		}
	}

	aptListsDir := "/var/lib/apt/lists"
	if files, err := os.ReadDir(aptListsDir); err == nil && len(files) > 0 {
		info.SignatureValid = boolPtr(true)
		info.Extra["repoSigned"] = true
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
		if strings.Contains(line, "is owned by") {
			parts := strings.Split(line, "is owned by")
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
				if strings.HasPrefix(line, "Packager") {
					packager := strings.TrimSpace(strings.TrimPrefix(line, "Packager"))
					packager = strings.TrimPrefix(packager, ":")
					packager = strings.TrimSpace(packager)
					if strings.Contains(packager, "archlinux.org") {
						info.SignerOrg = "Arch Linux"
						info.IsPlatform = true
					} else {
						info.Extra["packager"] = packager
					}
				}
				if strings.HasPrefix(line, "Validated By") {
					validated := strings.TrimSpace(strings.TrimPrefix(line, "Validated By"))
					validated = strings.TrimPrefix(validated, ":")
					validated = strings.TrimSpace(validated)
					if strings.Contains(validated, "Signature") {
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

func isOSVendor(vendor string) bool {
	osVendors := []string{
		"Red Hat", "RedHat", "Fedora", "CentOS", "Rocky", "AlmaLinux",
		"Ubuntu", "Debian", "Canonical",
		"SUSE", "openSUSE", "Alpine", "Arch Linux",
	}
	vendorLower := strings.ToLower(vendor)
	for _, v := range osVendors {
		if strings.Contains(vendorLower, strings.ToLower(v)) {
			return true
		}
	}
	return false
}
