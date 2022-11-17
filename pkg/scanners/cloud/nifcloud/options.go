package nifcloud

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableNIFCLOUDScanner interface {
	options.ConfigurableScanner
	SetProgressTracker(t progress.Tracker)
	SetNIFCLOUDRegion(region string)
	SetNIFCLOUDServices(services []string)
	SetConcurrencyStrategy(strategy concurrency.Strategy)
}

func ScannerWithProgressTracker(t progress.Tracker) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNIFCLOUDScanner); ok {
			nifcloud.SetProgressTracker(t)
		}
	}
}

func ScannerWithNIFCLOUDRegion(region string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNIFCLOUDScanner); ok {
			nifcloud.SetNIFCLOUDRegion(region)
		}
	}
}

func ScannerWithNIFCLOUDServices(services ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNIFCLOUDScanner); ok {
			nifcloud.SetNIFCLOUDServices(services)
		}
	}
}

func ScannerWithConcurrencyStrategy(strategy concurrency.Strategy) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNIFCLOUDScanner); ok {
			nifcloud.SetConcurrencyStrategy(strategy)
		}
	}
}
