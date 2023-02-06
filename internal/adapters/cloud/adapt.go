package cloud

import (
	"context"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/options"
	"github.com/aquasecurity/defsec/pkg/state"
)

// Adapt ...
func Adapt(
	ctx context.Context,
	opt options.Options,
	cloudAdapter func(ctx context.Context, state *state.State, opt options.Options) error) (*state.State, error) {
	cloudState := &state.State{}
	err := cloudAdapter(ctx, cloudState, opt)
	return cloudState, err
}
