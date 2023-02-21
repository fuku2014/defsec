package computing

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/nifcloud"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/nifcloud/nifcloud-sdk-go/service/computing"
)

type adapter struct {
	*nifcloud.RootAdapter
	client *computing.Client
}

func init() {
	nifcloud.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "nifcloud"
}

func (a *adapter) Name() string {
	return "computing"
}

func (a *adapter) Adapt(root *nifcloud.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = computing.NewFromConfig(root.SessionConfig())
	var err error

	state.Nifcloud.Computing.Instances, err = a.getInstances()
	if err != nil {
		return err
	}

	state.Nifcloud.Computing.SecurityGroups, err = a.getSecurityGroups()
	if err != nil {
		return err
	}

	return nil
}
