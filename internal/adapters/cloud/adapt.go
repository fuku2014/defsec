package cloud

import (
	"context"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/internal/adapters/cloud/nifcloud"
	"github.com/aquasecurity/defsec/internal/adapters/cloud/options"
	"github.com/aquasecurity/defsec/pkg/state"
)

// Adapt ...
func Adapt(ctx context.Context, opt options.Options) (*state.State, error) {
	cloudState := &state.State{}

	if opt.Provider == "aws" {
		if err := aws.Adapt(ctx, cloudState, opt); err != nil {
			return cloudState, err
		}
	}

	if opt.Provider == "nifcloud" {
		if err := nifcloud.Adapt(ctx, cloudState, opt); err != nil {
			return cloudState, err
		}
	}

	return cloudState, nil
}
