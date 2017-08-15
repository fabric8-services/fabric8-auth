package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Checks if the packageName is checked out into one of the GOPATH entries
// under GOPATH[i]/src/packageName.
func main() {
	var packageName string
	flag.StringVar(&packageName, "packageName", "github.com/fabric8-services/fabric8-auth", "Package Name (e.g.)")
	flag.Parse()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range strings.Split(os.Getenv("GOPATH"), string(filepath.ListSeparator)) {
		// Check if p is a directory
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			// Make sure we have an absolute path
			abs, err := filepath.Abs(p)
			if err != nil {
				log.Fatal(err)
			}
			if wd == filepath.Join(abs, "src", packageName) {
				os.Exit(0)
			}
		}
	}

	goPathStr := path.Join("$GOPATH", "src", packageName)
	if runtime.GOOS == "windows" {
		goPathStr = path.Join("%GOPATH%", "src", packageName)
	}
	log.Fatal(fmt.Errorf("Make sure you've checked out your project in %s", goPathStr))

}
