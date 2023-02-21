package dns

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/nifcloud"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/nifcloud/nifcloud-sdk-go/service/dns"
)

type adapter struct {
	*nifcloud.RootAdapter
	client *dns.Client
}

func init() {
	nifcloud.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "nifcloud"
}

func (a *adapter) Name() string {
	return "dns"
}

func (a *adapter) Adapt(root *nifcloud.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = dns.NewFromConfig(root.SessionConfig())
	var err error

	state.Nifcloud.DNS.Records, err = a.getRecords()
	if err != nil {
		return err
	}
	return nil
}
