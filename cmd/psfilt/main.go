// Package main implements psfilt, a tool that filters process output to show signature information.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HEXXDECIMAL/signedby-go/pkg/signedby"
)

type processInfo struct {
	line      string
	path      string
	pid       string
	fields    []string
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
		fmt.Fprint(os.Stderr, "Filter process list by signature status.\n\n")
		fmt.Fprint(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *unsignedOnly && *signedOnly {
		fmt.Fprint(os.Stderr, "Error: --unsigned and --signed are mutually exclusive\n")
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
	logger       *slog.Logger
	format       string
	timeout      time.Duration
	unsignedOnly bool
	signedOnly   bool
	platformOnly bool
	pidColumn    bool
	noCache      bool
}

func processPsOutput(input io.Reader, output io.Writer, opts *options) {
	scanner := bufio.NewScanner(input)
	var headerPrinted bool
	var processes []processInfo
	pathSet := make(map[string]bool)

	opts.logger.Debug("starting ps output processing")

	for scanner.Scan() {
		line := scanner.Text()

		if !headerPrinted {
			if printHeaderIfNeeded(output, line, opts) {
				headerPrinted = true
				continue
			}
		}

		proc, shouldContinue := parseProcessLine(line, opts)
		if shouldContinue {
			continue
		}

		processes = append(processes, proc)
		if proc.path != "" && !strings.HasPrefix(proc.path, "DELETED:") {
			pathSet[proc.path] = true
		}
	}

	opts.logger.Debug("found unique binaries", "count", len(pathSet))

	uniquePaths := collectUniquePaths(pathSet)
	results := verifyBinaries(uniquePaths, opts)

	displayProcessResults(output, processes, results, opts)
}

func printHeaderIfNeeded(output io.Writer, line string, opts *options) bool {
	if strings.Contains(line, "PID") || strings.Contains(line, "USER") || strings.Contains(line, "UID") {
		if opts.pidColumn {
			_, _ = fmt.Fprintf(output, "%s SIGNER\n", line) //nolint:errcheck // writing to output
		} else {
			_, _ = fmt.Fprintln(output, line) //nolint:errcheck // writing to output
		}
		return true
	}
	return false
}

func parseProcessLine(line string, opts *options) (processInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return processInfo{}, true
	}

	pid, command := extractPidAndCommand(fields)
	if pid == "" || command == "" {
		opts.logger.Debug("could not parse ps line", "line", line)
		return processInfo{}, true
	}

	// Extract ppid (usually field 2 in ps -afe output: UID PID PPID ...)
	ppid := ""
	if len(fields) > 2 {
		// Find the PID position first
		for i, field := range fields {
			if field == pid && i+1 < len(fields) {
				// PPID is the field right after PID
				ppid = fields[i+1]
				break
			}
		}
	}

	// Check if it's a kernel thread on Linux (ppid=2)
	if isKernelThread(pid, ppid) {
		opts.logger.Debug("detected kernel thread (ppid=2)", "pid", pid, "ppid", ppid, "command", command)
		if opts.unsignedOnly {
			// Skip kernel threads when showing unsigned only
			return processInfo{}, true
		}
		// Return a special process info for kernel threads - don't try to extract path
		return processInfo{
			line:      line,
			fields:    fields,
			path:      "KERNEL_THREAD", // Special marker
			pid:       pid,
			needsRoot: false,
		}, false
	}

	return createProcessInfo(line, fields, pid, command, opts), false
}

func extractPidAndCommand(fields []string) (pid string, command string) {
	for i, field := range fields {
		if i > 0 && i < 4 { // PID is usually in positions 1-3
			if _, err := strconv.Atoi(field); err == nil {
				pid = field
				cmdStartIdx := calculateCommandStartIndex(i, fields)
				if cmdStartIdx < len(fields) {
					command = strings.Join(fields[cmdStartIdx:], " ")
				}
				break
			}
		}
	}
	return pid, command
}

func calculateCommandStartIndex(pidIndex int, fields []string) int {
	// Default for ps -afe (UID PID PPID C STIME TTY TIME CMD)
	cmdStartIdx := pidIndex + 6
	if len(fields) > 10 && strings.Contains(fields[6], ":") && strings.Contains(fields[7], ":") {
		// Likely ps aux format (has STAT and START columns)
		cmdStartIdx = 10
	}
	return cmdStartIdx
}

func createProcessInfo(line string, fields []string, pid, command string, opts *options) processInfo {
	cmdPath, needsRoot := getExecutableForPID(pid, opts.logger)

	// Handle special cases
	if needsRoot {
		return processInfo{
			line:      line,
			fields:    fields,
			path:      "", // Empty path will be handled specially
			pid:       pid,
			needsRoot: true,
		}
	}

	if strings.HasPrefix(cmdPath, "DELETED:") {
		return processInfo{
			line:      line,
			fields:    fields,
			path:      cmdPath, // Keep the DELETED: prefix for special handling
			pid:       pid,
			needsRoot: false,
		}
	}

	if cmdPath == "" {
		cmdPath = extractPath(command, opts.logger)
		if cmdPath == "" {
			opts.logger.Debug("cannot determine path", "pid", pid, "command", command)
			return processInfo{
				line:      line,
				fields:    fields,
				path:      "", // Empty path for unresolvable
				pid:       pid,
				needsRoot: false,
			}
		}
	}

	return processInfo{
		line:      line,
		fields:    fields,
		path:      cmdPath,
		pid:       pid,
		needsRoot: false,
	}
}

func collectUniquePaths(pathSet map[string]bool) []string {
	uniquePaths := make([]string, 0, len(pathSet))
	for path := range pathSet {
		uniquePaths = append(uniquePaths, path)
	}
	return uniquePaths
}

func displayProcessResults(output io.Writer, processes []processInfo, results map[string]*signedby.SignatureInfo, opts *options) {
	for _, proc := range processes {
		switch {
		case proc.path == "KERNEL_THREAD":
			// Display kernel threads with special marker
			if !opts.signedOnly {
				displayProcess(output, proc, nil, opts)
			}
		case proc.needsRoot:
			// Always display processes that need root
			if !opts.signedOnly {
				displayProcess(output, proc, nil, opts)
			}
		case strings.HasPrefix(proc.path, "DELETED:"):
			// Always display deleted executables with special marker
			if !opts.signedOnly {
				displayProcess(output, proc, nil, opts)
			}
		case proc.path == "":
			// Process with unresolvable path
			if !opts.signedOnly {
				displayProcess(output, proc, nil, opts)
			}
		default:
			info := results[proc.path]
			if shouldDisplay(info, opts) {
				displayProcess(output, proc, info, opts)
			}
		}
	}
}

func getExecutableForPID(pid string, logger *slog.Logger) (string, bool) {
	// On Linux, first try /proc/<pid>/exe which is most reliable
	procExePath := "/proc/" + pid + "/exe"
	if target, err := os.Readlink(procExePath); err == nil {
		// Successfully read the symlink
		// Check if the executable has been deleted
		if strings.HasSuffix(target, " (deleted)") {
			// Return a special marker for deleted executables
			logger.Debug("executable is deleted", "pid", pid, "path", target)
			return "DELETED:" + strings.TrimSuffix(target, " (deleted)"), false
		}
		logger.Debug("got executable from /proc/PID/exe", "pid", pid, "path", target)
		return target, false
	} else if os.IsPermission(err) {
		// Permission denied - need root
		logger.Debug("need root access for /proc/PID/exe", "pid", pid, "error", err)
		// Try to get at least the command name for display
		cmdlinePath := "/proc/" + pid + "/cmdline"
		if cmdline, err := os.ReadFile(cmdlinePath); err == nil && len(cmdline) > 0 {
			// cmdline is null-separated, get first part
			parts := strings.Split(string(cmdline), "\x00")
			if len(parts) > 0 && parts[0] != "" {
				return parts[0], true // Return command and needsRoot=true
			}
		}
		return "", true
	}

	// Fallback to ps -p for non-Linux or if /proc is not available
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "ps", "-p", pid, "-o", "comm=")
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

	// For non-absolute paths, try to get the real binary using lsof as last resort
	cmd = exec.CommandContext(ctx, "lsof", "-p", pid)
	output, err = cmd.CombinedOutput()
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
	logger.Debug("cannot determine absolute path", "pid", pid, "path", path)
	return "", false
}

// isKernelThread checks if a process is a kernel thread on Linux.
// On Linux, all kernel threads have ppid=2 (kthreadd).
func isKernelThread(pid string, ppid string) bool {
	// Only check on Linux
	if runtime.GOOS != "linux" {
		return false
	}

	// All kernel threads have ppid=2 (kthreadd)
	return ppid == "2"
}

func extractPath(command string, logger *slog.Logger) string {
	command = strings.TrimSpace(command)

	if strings.HasPrefix(command, "[") && strings.HasSuffix(command, "]") {
		logger.Debug("skipping kernel process", "command", command)
		return ""
	}

	// Handle paths with spaces - look for common patterns
	// Try to find .app paths first (macOS specific)
	if appPath := extractAppBundlePath(command, logger); appPath != "" {
		return appPath
	}

	return extractSimplePath(command, logger)
}

func extractAppBundlePath(command string, logger *slog.Logger) string {
	if !strings.Contains(command, ".app/") {
		return ""
	}

	// Find the start of the path (usually starts with /)
	startIdx := strings.Index(command, "/")
	if startIdx < 0 {
		return ""
	}

	path := command[startIdx:]
	path = cleanAppBundlePath(path)
	path = strings.TrimSpace(path)
	logger.Debug("found app bundle path", "path", path)
	return path
}

func cleanAppBundlePath(path string) string {
	// Check if there's a flag argument first
	if idx := strings.Index(path, " -"); idx > 0 {
		return path[:idx]
	}

	// Look for space followed by another absolute path (likely an argument)
	return reconstructPathFromParts(path)
}

func reconstructPathFromParts(path string) string {
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
	return fullPath
}

func extractSimplePath(command string, logger *slog.Logger) string {
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

	return validateAndReturnPath(executable, logger)
}

func validateAndReturnPath(executable string, logger *slog.Logger) string {
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
	switch {
	case proc.path == "KERNEL_THREAD":
		signer = "kernel thread"
	case proc.needsRoot:
		signer = "need root"
	case strings.HasPrefix(proc.path, "DELETED:"):
		signer = "err: DELETED EXECUTABLE"
	case proc.path == "":
		signer = "unresolvable"
	default:
		signer = formatSigner(info)
	}

	switch {
	case opts.pidColumn:
		_, _ = fmt.Fprintf(output, "%s %s %s\n", proc.pid, proc.line, signer) //nolint:errcheck // writing to output
	case opts.format != "":
		formatted := opts.format
		formatted = strings.ReplaceAll(formatted, "%pid", proc.pid)
		formatted = strings.ReplaceAll(formatted, "%path", proc.path)
		formatted = strings.ReplaceAll(formatted, "%signer", signer)
		formatted = strings.ReplaceAll(formatted, "%line", proc.line)
		_, _ = fmt.Fprintln(output, formatted) //nolint:errcheck // writing to output
	default:
		_, _ = fmt.Fprintf(output, "%s [%s]\n", proc.line, signer) //nolint:errcheck // writing to output
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
