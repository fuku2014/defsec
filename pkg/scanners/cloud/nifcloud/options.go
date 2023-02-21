package nifcloud

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableNifcloudScanner interface {
	options.ConfigurableScanner
	SetProgressTracker(t progress.Tracker)
	SetNifcloudRegion(region string)
	SetNifcloudEndpoint(endpoint string)
	SetNifcloudServices(services []string)
	SetConcurrencyStrategy(strategy concurrency.Strategy)
}

func ScannerWithProgressTracker(t progress.Tracker) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNifcloudScanner); ok {
			nifcloud.SetProgressTracker(t)
		}
	}
}

func ScannerWithNifcloudRegion(region string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNifcloudScanner); ok {
			nifcloud.SetNifcloudRegion(region)
		}
	}
}

func ScannerWithNifcloudEndpoint(endpoint string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNifcloudScanner); ok {
			nifcloud.SetNifcloudEndpoint(endpoint)
		}
	}
}

func ScannerWithNifcloudServices(services ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNifcloudScanner); ok {
			nifcloud.SetNifcloudServices(services)
		}
	}
}

func ScannerWithConcurrencyStrategy(strategy concurrency.Strategy) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if nifcloud, ok := s.(ConfigurableNifcloudScanner); ok {
			nifcloud.SetConcurrencyStrategy(strategy)
		}
	}
}
