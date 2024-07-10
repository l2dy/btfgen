package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"

	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/btfhub/pkg/job"
	"github.com/l2dy/btfgen/pkg/centos"
)

var repoURL, arch string
var numWorkers int
var force bool

func init() {
	flag.StringVar(&repoURL, "r", "", ".rpm package directory URL")
	flag.StringVar(&arch, "a", "", "architecture to update (x86_64,aarch64)")
	flag.IntVar(&numWorkers, "workers", 0, "number of concurrent workers (defaults to runtime.NumCPU() - 1)")
	flag.IntVar(&numWorkers, "j", 0, "number of concurrent workers (defaults to runtime.NumCPU() - 1)")
	flag.BoolVar(&force, "f", false, "force update regardless of existing files (defaults to false)")
}

func main() {
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	if repoURL == "" {
		return fmt.Errorf("-r is required")
	}
	repo, err := url.Parse(repoURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %s", err)
	}

	// Architectures

	archs := []string{"x86_64", "aarch64"}
	if arch != "" {
		archs = []string{arch}
	}

	// Environment

	basedir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("pwd: %s", err)
	}
	archiveDir := path.Join(basedir, "archive")

	if numWorkers == 0 {
		numWorkers = runtime.NumCPU() - 1
		if numWorkers > 12 {
			numWorkers = 12 // limit to 12 workers max (for bigger machines)
		}
	}

	// Workers: job consumers (pool)

	jobChan := make(chan job.Job)
	consume, consCtx := errgroup.WithContext(ctx)

	log.Printf("Using %d workers\n", numWorkers)
	for i := 0; i < numWorkers; i++ {
		consume.Go(func() error {
			return job.StartWorker(consCtx, jobChan)
		})
	}

	// Workers: job producers (per distro, per release)

	produce, prodCtx := errgroup.WithContext(ctx)

	for _, a := range archs {
		arch := a
		produce.Go(func() error {
			// workDir example: ./archive/example.lan/x86_64
			workDir := filepath.Join(archiveDir, repo.Host, arch)
			if err := os.MkdirAll(workDir, 0775); err != nil {
				return fmt.Errorf("arch dir: %s", err)
			}

			return centos.GetKernelPackages(prodCtx, workDir, repoURL, arch, force, jobChan)
		})

	}

	// Cleanup

	err = produce.Wait()
	close(jobChan)
	if err != nil {
		return err
	}

	return consume.Wait()
}
