package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tstromberg/signedby-go/pkg/signedby"
)

type processInfo struct {
	line      string
	fields    []string
	path      string
	pid       string
	needsRoot bool
}

func main() {
	var (
		unsignedOnly = flag.Bool("unsigned", false, "Only show unsigned processes")
		signedOnly   = flag.Bool("signed", false, "Only show signed processes")
		platformOnly = flag.Bool("platform", false, "Only show platform binaries")
		pidColumn    = flag.Bool("pid-column", false, "Output PID in a separate column")
		format       = flag.String("format", "", "Custom output format")
		noCache      = flag.Bool("no-cache", false, "Skip cache")
		timeout      = flag.Duration("timeout", 5*time.Second, "Timeout per binary verification")
		debug        = flag.Bool("debug", false, "Enable debug logging")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ps aux | %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Filter process list by signature status.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *unsignedOnly && *signedOnly {
		fmt.Fprintf(os.Stderr, "Error: --unsigned and --signed are mutually exclusive\n")
		os.Exit(1)
	}

	// Setup logger - always log errors to stderr, debug if requested
	var logger *slog.Logger
	if *debug {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError,
		}))
	}

	processPsOutput(os.Stdin, os.Stdout, &options{
		unsignedOnly: *unsignedOnly,
		signedOnly:   *signedOnly,
		platformOnly: *platformOnly,
		pidColumn:    *pidColumn,
		format:       *format,
		noCache:      *noCache,
		timeout:      *timeout,
		logger:       logger,
	})
}

type options struct {
	unsignedOnly bool
	signedOnly   bool
	platformOnly bool
	pidColumn    bool
	format       string
	noCache      bool
	timeout      time.Duration
	logger       *slog.Logger
}

func processPsOutput(input io.Reader, output io.Writer, opts *options) {
	scanner := bufio.NewScanner(input)
	var headerPrinted bool
	var processes []processInfo
	pathSet := make(map[string]bool)

	opts.logger.Debug("starting ps output processing")

	psPattern := regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$`)

	for scanner.Scan() {
		line := scanner.Text()

		if !headerPrinted {
			if strings.Contains(line, "PID") || strings.Contains(line, "USER") {
				if opts.pidColumn {
					fmt.Fprintf(output, "%s SIGNER\n", line)
				} else {
					fmt.Fprintln(output, line)
				}
				headerPrinted = true
				continue
			}
		}

		matches := psPattern.FindStringSubmatch(line)
		if len(matches) < 12 {
			continue
		}

		pid := matches[2]
		command := matches[11]

		// Get the actual executable path using ps -p <pid>
		cmdPath, needsRoot := getExecutableForPID(pid, opts.logger)

		// Handle special cases
		if needsRoot {
			// Mark this process as needing root but still show it
			proc := processInfo{
				line:      line,
				fields:    matches[1:],
				path:      "", // Empty path will be handled specially
				pid:       pid,
				needsRoot: true,
			}
			processes = append(processes, proc)
			continue
		}

		if cmdPath == "" {
			// Fallback to parsing command if ps -p fails
			cmdPath = extractPath(command, opts.logger)
			if cmdPath == "" {
				opts.logger.Debug("skipping process - no path", "pid", pid, "command", command)
				continue
			}
		}

		proc := processInfo{
			line:      line,
			fields:    matches[1:],
			path:      cmdPath,
			pid:       pid,
			needsRoot: false,
		}
		processes = append(processes, proc)
		pathSet[cmdPath] = true
	}

	opts.logger.Debug("found unique binaries", "count", len(pathSet))

	uniquePaths := make([]string, 0, len(pathSet))
	for path := range pathSet {
		uniquePaths = append(uniquePaths, path)
	}

	results := verifyBinaries(uniquePaths, opts)

	for _, proc := range processes {
		if proc.needsRoot {
			// Always display processes that need root
			if !opts.signedOnly {
				displayProcess(output, proc, nil, opts)
			}
		} else {
			info := results[proc.path]
			if shouldDisplay(info, opts) {
				displayProcess(output, proc, info, opts)
			}
		}
	}
}

func getExecutableForPID(pid string, logger *slog.Logger) (string, bool) {
	// First try ps -p <pid> -o comm= to get the executable path
	cmd := exec.Command("ps", "-p", pid, "-o", "comm=")
	output, err := cmd.Output()
	if err != nil {
		logger.Debug("failed to get executable for PID", "pid", pid, "error", err)
		return "", false
	}

	path := strings.TrimSpace(string(output))
	if path == "" {
		return "", false
	}

	// If it's already an absolute path, use it
	if filepath.IsAbs(path) {
		logger.Debug("got absolute path from ps", "pid", pid, "path", path)
		return path, false
	}

	// For non-absolute paths, try to get the real binary using lsof
	// Look specifically for the txt (text/executable) file descriptor
	cmd = exec.Command("sh", "-c", fmt.Sprintf("lsof -p %s 2>&1", pid))
	output, err = cmd.Output()
	outputStr := string(output)

	// Check if we need root access
	if err != nil && (strings.Contains(outputStr, "Permission denied") ||
	                  strings.Contains(outputStr, "Operation not permitted")) {
		logger.Debug("need root access for PID", "pid", pid, "path", path)
		return path, true // Return path and needsRoot=true
	}

	// Parse lsof output if successful
	if err == nil {
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, "txt") {
				fields := strings.Fields(line)
				if len(fields) >= 9 && fields[3] == "txt" {
					execPath := fields[len(fields)-1]
					if filepath.IsAbs(execPath) {
						logger.Debug("got executable from lsof", "pid", pid, "path", execPath)
						return execPath, false
					}
				}
			}
		}
	}

	// For security, we do NOT search PATH or try to guess locations
	// If we can't determine the absolute path, we won't verify it
	logger.Debug("cannot determine absolute path", "pid", pid, "path", path)
	return "", false
}

func extractPath(command string, logger *slog.Logger) string {
	command = strings.TrimSpace(command)

	if strings.HasPrefix(command, "[") && strings.HasSuffix(command, "]") {
		logger.Debug("skipping kernel process", "command", command)
		return ""
	}

	// Handle paths with spaces - look for common patterns
	// Try to find .app paths first (macOS specific)
	if strings.Contains(command, ".app/") {
		// Find the start of the path (usually starts with /)
		startIdx := strings.Index(command, "/")
		if startIdx >= 0 {
			path := command[startIdx:]

			// For .app bundles with spaces, we need to be careful
			// Check if there's a flag argument first
			if idx := strings.Index(path, " -"); idx > 0 {
				path = path[:idx]
			} else {
				// Look for space followed by another absolute path (likely an argument)
				// Split by spaces and reconstruct
				parts := strings.Split(path, " ")
				fullPath := ""
				for i, part := range parts {
					// If we encounter another absolute path, stop
					if i > 0 && strings.HasPrefix(part, "/") {
						break
					}
					// If we encounter a flag, stop
					if strings.HasPrefix(part, "-") {
						break
					}
					if fullPath != "" {
						fullPath += " "
					}
					fullPath += part
				}
				path = fullPath
			}

			path = strings.TrimSpace(path)
			logger.Debug("found app bundle path", "path", path)
			return path
		}
	}

	// Fall back to simple field splitting for paths without spaces
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}

	executable := parts[0]

	if strings.HasPrefix(executable, "(") && strings.HasSuffix(executable, ")") {
		logger.Debug("skipping parenthesized process", "command", command)
		return ""
	}

	executable = strings.TrimSuffix(executable, ":")

	if filepath.IsAbs(executable) {
		logger.Debug("found absolute path", "path", executable)
		return executable
	}

	if strings.Contains(executable, "/") {
		logger.Debug("found relative path", "path", executable)
		return executable
	}

	// For security, we do NOT search PATH or try to guess locations
	// If we can't determine the absolute path, we won't verify it
	logger.Debug("cannot determine absolute path", "executable", executable)
	return ""
}

func verifyBinaries(paths []string, opts *options) map[string]*signedby.SignatureInfo {
	results := make(map[string]*signedby.SignatureInfo)
	mu := sync.Mutex{}

	opts.logger.Debug("verifying binaries", "count", len(paths))

	var verifier signedby.Verifier
	if opts.noCache {
		verifier = signedby.NewWithLogger(opts.logger, false)
	} else {
		verifier = signedby.NewWithLogger(opts.logger, true)
	}

	wg := sync.WaitGroup{}
	semaphore := make(chan struct{}, 10)

	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			opts.logger.Debug("verifying binary", "path", p)
			info, err := verifier.VerifyWithOptions(p, signedby.VerifyOptions{
				UseCache:       !opts.noCache,
				SkipValidation: true,
				Timeout:        opts.timeout,
				Logger:         opts.logger,
			})

			if err != nil {
				opts.logger.Debug("verification failed", "path", p, "error", err)
			}

			mu.Lock()
			results[p] = info
			mu.Unlock()
		}(path)
	}

	wg.Wait()
	return results
}

func shouldDisplay(info *signedby.SignatureInfo, opts *options) bool {
	if info == nil {
		return !opts.signedOnly
	}

	isSigned := info.SignatureValid != nil && *info.SignatureValid

	if opts.unsignedOnly && isSigned {
		return false
	}
	if opts.signedOnly && !isSigned {
		return false
	}
	if opts.platformOnly && !info.IsPlatform {
		return false
	}

	return true
}

func displayProcess(output io.Writer, proc processInfo, info *signedby.SignatureInfo, opts *options) {
	var signer string
	if proc.needsRoot {
		signer = "need root"
	} else {
		signer = formatSigner(info)
	}

	if opts.pidColumn {
		fmt.Fprintf(output, "%s %s %s\n", proc.pid, proc.line, signer)
	} else if opts.format != "" {
		formatted := opts.format
		formatted = strings.ReplaceAll(formatted, "%pid", proc.pid)
		formatted = strings.ReplaceAll(formatted, "%path", proc.path)
		formatted = strings.ReplaceAll(formatted, "%signer", signer)
		formatted = strings.ReplaceAll(formatted, "%line", proc.line)
		fmt.Fprintln(output, formatted)
	} else {
		fmt.Fprintf(output, "%s [%s]\n", proc.line, signer)
	}
}

func formatSigner(info *signedby.SignatureInfo) string {
	if info == nil {
		return "error"
	}

	// Check if this is an actual error vs just unsigned
	if _, hasError := info.Extra["error"]; hasError {
		return "error"
	}

	if info.SignatureValid != nil && !*info.SignatureValid {
		return "unsigned"
	}

	if info.SignerOrg != "" {
		return info.SignerOrg
	}

	if info.IsPackaged {
		return fmt.Sprintf("pkg:%s", info.PackageName)
	}

	if info.PackageName != "" {
		return fmt.Sprintf("id:%s", info.PackageName)
	}

	return "unknown"
}
