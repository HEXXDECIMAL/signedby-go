package signedby

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	v := New()
	if v == nil {
		t.Fatal("New() returned nil")
	}

	verifier, ok := v.(*verifier)
	if !ok {
		t.Fatal("New() did not return a *verifier")
	}

	if verifier.cache != nil {
		t.Error("New() should not initialize cache")
	}
}

func TestNewWithCache(t *testing.T) {
	v := NewWithCache()
	if v == nil {
		t.Fatal("NewWithCache() returned nil")
	}

	verifier, ok := v.(*verifier)
	if !ok {
		t.Fatal("NewWithCache() did not return a *verifier")
	}

	if verifier.cache == nil {
		t.Error("NewWithCache() should initialize cache")
	}
}

func TestVerifyBasic(t *testing.T) {
	v := New()

	var testPath string
	switch runtime.GOOS {
	case "darwin":
		testPath = "/bin/ls"
	case "linux":
		testPath = "/bin/ls"
		if _, err := os.Stat(testPath); err != nil {
			testPath = "/usr/bin/ls"
		}
	case "windows":
		testPath = "C:\\Windows\\System32\\cmd.exe"
	default:
		t.Skip("Unsupported platform for test")
	}

	if _, err := os.Stat(testPath); err != nil {
		t.Skipf("Test binary not found: %s", testPath)
	}

	info, err := v.Verify(testPath)
	if err != nil {
		t.Fatalf("Verify(%s) failed: %v", testPath, err)
	}

	if info.Path != testPath {
		t.Errorf("Path mismatch: got %s, want %s", info.Path, testPath)
	}

	switch runtime.GOOS {
	case "darwin":
		if info.SigningMethod != "codesign" {
			t.Errorf("Expected signing method 'codesign', got %s", info.SigningMethod)
		}
		if !info.IsPlatform {
			t.Error("Expected /bin/ls to be a platform binary on macOS")
		}
	case "linux":
		if info.SigningMethod == "" {
			t.Error("Expected a signing method on Linux")
		}
	case "windows":
		if info.SigningMethod != "authenticode" {
			t.Errorf("Expected signing method 'authenticode', got %s", info.SigningMethod)
		}
		if !info.IsPlatform {
			t.Error("Expected cmd.exe to be a platform binary on Windows")
		}
	}
}

func TestVerifyNonExistent(t *testing.T) {
	v := New()
	_, err := v.Verify("/path/that/does/not/exist/binary")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestVerifyWithOptions(t *testing.T) {
	v := New()

	var testPath string
	switch runtime.GOOS {
	case "darwin":
		testPath = "/usr/bin/true"
	case "linux":
		testPath = "/usr/bin/true"
	case "windows":
		testPath = "C:\\Windows\\System32\\ping.exe"
	default:
		t.Skip("Unsupported platform for test")
	}

	if _, err := os.Stat(testPath); err != nil {
		t.Skipf("Test binary not found: %s", testPath)
	}

	opts := VerifyOptions{
		UseCache:       false,
		SkipValidation: true,
		Timeout:        10 * time.Second,
	}

	info, err := v.VerifyWithOptions(testPath, opts)
	if err != nil {
		t.Fatalf("VerifyWithOptions(%s) failed: %v", testPath, err)
	}

	if info.Path != testPath {
		t.Errorf("Path mismatch: got %s, want %s", info.Path, testPath)
	}
}

func TestBoolPtr(t *testing.T) {
	truePtr := boolPtr(true)
	if truePtr == nil || *truePtr != true {
		t.Error("boolPtr(true) failed")
	}

	falsePtr := boolPtr(false)
	if falsePtr == nil || *falsePtr != false {
		t.Error("boolPtr(false) failed")
	}
}
