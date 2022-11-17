package computing

import (
	nifcloud2 "github.com/aquasecurity/defsec/internal/adapters/cloud/nifcloud"
	"github.com/aquasecurity/defsec/pkg/state"
	computingapi "github.com/nifcloud/nifcloud-sdk-go/service/computing"
)

type adapter struct {
	*nifcloud2.RootAdapter
	client *computingapi.Client
}

func init() {
	nifcloud2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "nifcloud"
}

func (a *adapter) Name() string {
	return "computing"
}

func (a *adapter) Adapt(root *nifcloud2.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = computingapi.NewFromConfig(root.SessionConfig())
	var err error

	state.NIFCLOUD.COMPUTING.SecurityGroups, err = a.getSecurityGroups()
	if err != nil {
		return err
	}

	return nil
}
