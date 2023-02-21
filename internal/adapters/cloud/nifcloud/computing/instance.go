package computing

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/nifcloud/nifcloud-sdk-go/nifcloud"
	"github.com/nifcloud/nifcloud-sdk-go/service/computing/types"
)

func (a *adapter) getInstances() (instances []computing.Instance, err error) {

	a.Tracker().SetServiceLabel("Discovering instances...")

	output, err := a.client.DescribeInstances(a.Context(), nil)
	if err != nil {
		return nil, err
	}

	a.Tracker().SetTotalResources(len(output.ReservationSet))
	a.Tracker().SetServiceLabel("Adapting instances...")
	return concurrency.Adapt(output.ReservationSet, a.RootAdapter, a.adaptInstance), nil
}

func (a *adapter) adaptInstance(instance types.ReservationSet) (*computing.Instance, error) {
	item := instance.InstancesSet[0]

	instanceMetadata := a.CreateMetadata("instance/" + nifcloud.ToString(item.InstanceId))

	sg := ""
	if len(instance.GroupSet) > 0 {
		sg = nifcloud.ToString(instance.GroupSet[0].GroupId)
	}

	var networkInterfaces []computing.NetworkInterface
	for _, ni := range item.NetworkInterfaceSet {
		networkInterfaces = append(networkInterfaces, computing.NetworkInterface{
			Metadata:  instanceMetadata,
			NetworkID: defsecTypes.String(nifcloud.ToString(ni.NiftyNetworkId), instanceMetadata),
		})
	}

	i := &computing.Instance{
		Metadata:          instanceMetadata,
		SecurityGroup:     defsecTypes.String(sg, instanceMetadata),
		NetworkInterfaces: networkInterfaces,
	}
	return i, nil
}
