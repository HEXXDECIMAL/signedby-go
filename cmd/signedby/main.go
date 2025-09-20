package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/HEXXDECIMAL/signedby-go/pkg/signedby"
)

func main() {
	var (
		jsonOutput = flag.Bool("json", false, "Output in JSON format")
		noCache    = flag.Bool("no-cache", false, "Skip cache")
		fast       = flag.Bool("fast", false, "Skip signature validation for faster results")
		timeout    = flag.Duration("timeout", 30*time.Second, "Timeout for verification")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Verify the signature and origin of a binary file.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	path := flag.Arg(0)

	var verifier signedby.Verifier
	if *noCache {
		verifier = signedby.New()
	} else {
		verifier = signedby.NewWithCache()
	}

	opts := signedby.VerifyOptions{
		UseCache:       !*noCache,
		SkipValidation: *fast,
		Timeout:        *timeout,
	}

	info, err := verifier.VerifyWithOptions(path, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(info); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		printInfo(info)
	}
}

func printInfo(info *signedby.SignatureInfo) {
	fmt.Printf("Path: %s\n", info.Path)

	if info.IsPackaged || info.PackageName != "" {
		if info.PackageVersion != "" {
			fmt.Printf("Package: %s %s\n", info.PackageName, info.PackageVersion)
		} else if info.PackageName != "" {
			fmt.Printf("Package: %s\n", info.PackageName)
		} else {
			fmt.Println("Package: Unknown")
		}
	} else {
		fmt.Println("Package: Not from a package")
	}

	if info.SignerOrg != "" {
		fmt.Printf("Signed by: %s\n", info.SignerOrg)
	} else {
		fmt.Println("Signed by: Unknown")
	}

	fmt.Printf("Platform: %v\n", yesNo(info.IsPlatform))

	if info.SigningMethod != "" {
		fmt.Printf("Method: %s\n", info.SigningMethod)
	}

	if info.SignatureValid != nil {
		fmt.Printf("Valid: %v\n", yesNo(*info.SignatureValid))
	} else {
		fmt.Println("Valid: Unknown")
	}

	if len(info.Extra) > 0 && os.Getenv("VERBOSE") != "" {
		fmt.Println("\nExtra information:")
		for k, v := range info.Extra {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
