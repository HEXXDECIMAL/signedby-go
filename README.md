# signedby-go

A Go library and tools to identify where binaries came from and who signed them.

## Features

- Identifies if a binary is from an installed package
- Reports package name and version
- Identifies the signing organization
- Detects platform/OS vendor binaries
- Shows signature validation status
- Fast with optional caching
- Cross-platform support (macOS, Windows, Linux, FreeBSD)

## Installation

```bash
go install github.com/tstromberg/signedby-go/cmd/signedby@latest
go install github.com/tstromberg/signedby-go/cmd/psfilt@latest
```

## Command-Line Tools

### signedby

Verify a single binary:

```bash
signedby /usr/bin/ls
# Output:
# Path: /usr/bin/ls
# Package: coreutils 9.1-1
# Signed by: Ubuntu
# Platform: Yes
# Method: dpkg
# Valid: Yes

# JSON output
signedby --json /usr/bin/curl

# Skip cache for fresh results
signedby --no-cache /usr/local/bin/kubectl

# Fast mode (skip signature validation)
signedby --fast /usr/bin/python3
```

### psfilt

Filter process list by signature status:

```bash
# Append signature info to process list
ps aux | psfilt

# Show only unsigned processes
ps aux | psfilt --unsigned

# Show only signed processes
ps aux | psfilt --signed

# Show only platform binaries
ps aux | psfilt --platform

# Add PID as separate column
ps aux | psfilt --pid-column
```

## Library Usage

```go
import "github.com/tstromberg/signedby-go/pkg/signedby"

// Simple usage
verifier := signedby.New()
info, err := verifier.Verify("/usr/bin/ls")
if err != nil {
    log.Printf("Warning: %v", err)
}

fmt.Printf("Binary: %s\n", info.Path)
if info.IsPackaged {
    fmt.Printf("Package: %s %s\n", info.PackageName, info.PackageVersion)
}
if info.SignerOrg != "" {
    fmt.Printf("Signed by: %s\n", info.SignerOrg)
}
if info.IsPlatform {
    fmt.Println("This is a platform/OS vendor binary")
}

// With caching enabled
verifier := signedby.NewWithCache()
info, err := verifier.VerifyWithOptions("/usr/bin/ls", signedby.VerifyOptions{
    UseCache:       true,
    SkipValidation: false,  // Set to true for faster results
    Timeout:        30 * time.Second,
})
```

## Platform Support

### Primary Platforms

- **macOS**: Uses `codesign` for verification
- **Windows**: Uses Authenticode signatures via PowerShell
- **Linux (RPM-based)**: Red Hat, Fedora, SUSE - checks rpm database
- **Linux (DEB-based)**: Debian, Ubuntu - checks dpkg database
- **Linux (Alpine)**: Checks apk package database
- **Linux (Arch)**: Checks pacman database
- **FreeBSD**: Checks pkg database

## API

### Types

```go
type SignatureInfo struct {
    Path           string                 // Path to the binary
    IsPackaged     bool                   // From an installed package?
    PackageName    string                 // Package name (if applicable)
    PackageVersion string                 // Package version
    SignerOrg      string                 // Organization that signed it
    IsPlatform     bool                   // Is this from the OS vendor?
    SigningMethod  string                 // How it was signed
    SignatureValid *bool                  // nil=unknown, true/false=verified
    Extra          map[string]interface{} // Platform-specific data
}

type Verifier interface {
    Verify(path string) (*SignatureInfo, error)
    VerifyWithOptions(path string, opts VerifyOptions) (*SignatureInfo, error)
}

type VerifyOptions struct {
    UseCache       bool
    SkipValidation bool          // Skip expensive signature validation
    Timeout        time.Duration
}
```

## Caching

The library caches verification results for 24 hours to improve performance. Cache is stored in:

- Linux/FreeBSD: `$XDG_CACHE_HOME/signedby` or `~/.cache/signedby`
- macOS: `~/Library/Caches/signedby`
- Windows: `%LOCALAPPDATA%\signedby`

Cache entries are invalidated when file metadata changes (size, mtime, permissions).

## Building

```bash
# Build everything
go build ./...

# Run tests
go test ./...

# Build CLI tools
go build -o signedby ./cmd/signedby
go build -o psfilt ./cmd/psfilt
```

## License

MIT

## Contributing

Pull requests welcome! Please ensure:

1. Code follows Go best practices
2. Tests pass (`go test ./...`)
3. No CGO dependencies
4. Minimal external dependencies