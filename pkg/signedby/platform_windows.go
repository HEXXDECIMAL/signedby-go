//go:build windows

package signedby

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

func verifyWindows(ctx context.Context, path string, opts VerifyOptions) (*SignatureInfo, error) {
	info := &SignatureInfo{
		Path:          path,
		SigningMethod: "authenticode",
		Extra:         make(map[string]any),
	}

	psScript := `
		$sig = Get-AuthenticodeSignature -FilePath '%s'
		@{
			Status = $sig.Status
			StatusMessage = $sig.StatusMessage
			SignerCertificate = if ($sig.SignerCertificate) {
				@{
					Subject = $sig.SignerCertificate.Subject
					Issuer = $sig.SignerCertificate.Issuer
					Thumbprint = $sig.SignerCertificate.Thumbprint
				}
			} else { $null }
			TimeStamperCertificate = if ($sig.TimeStamperCertificate) {
				@{
					Subject = $sig.TimeStamperCertificate.Subject
				}
			} else { $null }
			IsOSBinary = $sig.IsOSBinary
		} | ConvertTo-Json -Compress
	`

	psScript = strings.ReplaceAll(psScript, "'", "`")
	psScript = strings.ReplaceAll(psScript, "%s", strings.ReplaceAll(path, `\`, `\\`))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		info.Extra["error"] = err.Error()
		info.Extra["stderr"] = stderr.String()
		return info, nil
	}

	output := stdout.String()
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, `"Status":"Valid"`) {
			info.SignatureValid = boolPtr(true)
		} else if strings.Contains(line, `"Status":"NotSigned"`) {
			info.SignatureValid = boolPtr(false)
		} else if strings.Contains(line, `"Status":"`) {
			info.SignatureValid = boolPtr(false)
		}

		if strings.Contains(line, `"Subject":"`) {
			start := strings.Index(line, `"Subject":"`) + len(`"Subject":"`)
			end := strings.Index(line[start:], `"`)
			if end > 0 {
				subject := line[start : start+end]
				info.SignerOrg = extractOrgFromWindowsSubject(subject)
				info.Extra["subject"] = subject
			}
		}

		if strings.Contains(line, `"IsOSBinary":true`) {
			info.IsPlatform = true
		}

		if strings.Contains(line, `"StatusMessage":"`) {
			start := strings.Index(line, `"StatusMessage":"`) + len(`"StatusMessage":"`)
			end := strings.Index(line[start:], `"`)
			if end > 0 {
				info.Extra["statusMessage"] = line[start : start+end]
			}
		}

		if strings.Contains(line, `"Thumbprint":"`) {
			start := strings.Index(line, `"Thumbprint":"`) + len(`"Thumbprint":"`)
			end := strings.Index(line[start:], `"`)
			if end > 0 {
				info.Extra["thumbprint"] = line[start : start+end]
			}
		}
	}

	if info.SignerOrg != "" && strings.Contains(strings.ToLower(info.SignerOrg), "microsoft") {
		info.IsPlatform = true
	}

	checkInstalledPackage(ctx, path, info)

	return info, nil
}

func extractOrgFromWindowsSubject(subject string) string {
	if strings.Contains(subject, "CN=") {
		parts := strings.Split(subject, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "CN=") {
				cn := strings.TrimPrefix(part, "CN=")
				cn = strings.Trim(cn, `"`)
				return cn
			}
		}
	}
	return subject
}

func checkInstalledPackage(ctx context.Context, path string, info *SignatureInfo) {
	psScript := `
		$file = '%s'
		$programs = @()
		$programs += Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
		$programs += Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
		$programs += Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"

		foreach ($prog in $programs) {
			if ($prog.InstallLocation -and $file.StartsWith($prog.InstallLocation)) {
				@{
					DisplayName = $prog.DisplayName
					DisplayVersion = $prog.DisplayVersion
					Publisher = $prog.Publisher
				} | ConvertTo-Json -Compress
				break
			}
		}
	`

	psScript = strings.ReplaceAll(psScript, "'", "`")
	psScript = strings.ReplaceAll(psScript, "%s", strings.ReplaceAll(path, `\`, `\\`))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psScript)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err == nil {
		output := strings.TrimSpace(stdout.String())
		if output != "" && strings.Contains(output, "DisplayName") {
			info.IsPackaged = true

			if strings.Contains(output, `"DisplayName":"`) {
				start := strings.Index(output, `"DisplayName":"`) + len(`"DisplayName":"`)
				end := strings.Index(output[start:], `"`)
				if end > 0 {
					info.PackageName = output[start : start+end]
				}
			}

			if strings.Contains(output, `"DisplayVersion":"`) {
				start := strings.Index(output, `"DisplayVersion":"`) + len(`"DisplayVersion":"`)
				end := strings.Index(output[start:], `"`)
				if end > 0 {
					info.PackageVersion = output[start : start+end]
				}
			}

			if strings.Contains(output, `"Publisher":"`) && info.SignerOrg == "" {
				start := strings.Index(output, `"Publisher":"`) + len(`"Publisher":"`)
				end := strings.Index(output[start:], `"`)
				if end > 0 {
					publisher := output[start : start+end]
					info.SignerOrg = publisher
					if strings.Contains(strings.ToLower(publisher), "microsoft") {
						info.IsPlatform = true
					}
				}
			}
		}
	}

	wingetCheck := exec.CommandContext(ctx, "winget", "list", "--accept-source-agreements")
	if err := wingetCheck.Run(); err == nil {
		cmd = exec.CommandContext(ctx, "powershell", "-Command",
			`winget list --accept-source-agreements | Select-String '`+path+`'`)
		stdout.Reset()
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil {
			output := stdout.String()
			if output != "" {
				lines := strings.Split(output, "\n")
				for _, line := range lines {
					fields := strings.Fields(line)
					if len(fields) >= 2 && !info.IsPackaged {
						info.IsPackaged = true
						info.PackageName = fields[0]
						if len(fields) >= 3 {
							info.PackageVersion = fields[1]
						}
						info.Extra["winget"] = true
					}
				}
			}
		}
	}
}
