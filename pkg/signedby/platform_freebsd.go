//go:build freebsd

package signedby

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

func verifyFreeBSD(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	info := &SignatureInfo{
		Path:          path,
		SigningMethod: "pkg",
		Extra:         make(map[string]any),
	}

	cmd := exec.CommandContext(ctx, "pkg", "which", path)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		info.IsPackaged = false
		return info, nil
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" || strings.Contains(output, "not found") {
		info.IsPackaged = false
		return info, nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "was installed by package") {
			parts := strings.Split(line, "was installed by package")
			if len(parts) > 1 {
				pkgName := strings.TrimSpace(parts[1])
				pkgParts := strings.Split(pkgName, "-")
				if len(pkgParts) >= 2 {
					info.PackageName = strings.Join(pkgParts[:len(pkgParts)-1], "-")
					info.PackageVersion = pkgParts[len(pkgParts)-1]
				} else {
					info.PackageName = pkgName
				}
				info.IsPackaged = true
				break
			}
		}
	}

	if info.PackageName != "" {
		cmd = exec.CommandContext(ctx, "pkg", "info", info.PackageName)
		stdout.Reset()
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			output := stdout.String()
			for _, line := range strings.Split(output, "\n") {
				line = strings.TrimSpace(line)

				if strings.HasPrefix(line, "Origin") {
					origin := strings.TrimSpace(strings.TrimPrefix(line, "Origin"))
					origin = strings.TrimPrefix(origin, ":")
					origin = strings.TrimSpace(origin)
					info.Extra["origin"] = origin
					if strings.Contains(origin, "FreeBSD") {
						info.SignerOrg = "FreeBSD"
						info.IsPlatform = true
					}
				}

				if strings.HasPrefix(line, "Maintainer") {
					maintainer := strings.TrimSpace(strings.TrimPrefix(line, "Maintainer"))
					maintainer = strings.TrimPrefix(maintainer, ":")
					maintainer = strings.TrimSpace(maintainer)
					info.Extra["maintainer"] = maintainer
					if strings.Contains(maintainer, "@FreeBSD.org") {
						if info.SignerOrg == "" {
							info.SignerOrg = "FreeBSD"
						}
						info.IsPlatform = true
					}
				}

				if strings.HasPrefix(line, "Version") && info.PackageVersion == "" {
					version := strings.TrimSpace(strings.TrimPrefix(line, "Version"))
					version = strings.TrimPrefix(version, ":")
					info.PackageVersion = strings.TrimSpace(version)
				}
			}
		}

		cmd = exec.CommandContext(ctx, "pkg", "query", "%?s", info.PackageName)
		stdout.Reset()
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			output := strings.TrimSpace(stdout.String())
			if output == "1" {
				info.SignatureValid = boolPtr(true)
			} else if output == "0" {
				info.SignatureValid = boolPtr(false)
			}
		}
	}

	cmd = exec.CommandContext(ctx, "pkg", "config", "SIGNATURE_TYPE")
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		sigType := strings.TrimSpace(stdout.String())
		if sigType != "" && sigType != "NONE" {
			info.Extra["signatureType"] = sigType
			if info.SignatureValid == nil {
				info.SignatureValid = boolPtr(true)
			}
		}
	}

	return info, nil
}
