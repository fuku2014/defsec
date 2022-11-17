package computing

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/nifcloud/nifcloud-sdk-go/nifcloud"
	computingapi "github.com/nifcloud/nifcloud-sdk-go/service/computing"
	"github.com/nifcloud/nifcloud-sdk-go/service/computing/types"
)

func (a *adapter) getSecurityGroups() (securityGroups []computing.SecurityGroup, err error) {

	a.Tracker().SetServiceLabel("Discovering security groups...")

	var apiSecurityGroups []types.SecurityGroupInfo

	output, err := a.client.DescribeSecurityGroups(a.Context(), &computingapi.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}
	apiSecurityGroups = output.SecurityGroupInfo
	a.Tracker().SetTotalResources(len(apiSecurityGroups))

	a.Tracker().SetServiceLabel("Adapting security groups...")
	return concurrency.Adapt(apiSecurityGroups, a.RootAdapter, a.adaptSecurityGroup), nil
}

func (a *adapter) adaptSecurityGroup(apiSecurityGroup types.SecurityGroupInfo) (*computing.SecurityGroup, error) {

	sgMetadata := a.CreateMetadata("security-group/" + *apiSecurityGroup.GroupName)

	sg := &computing.SecurityGroup{
		Metadata:    sgMetadata,
		Description: defsecTypes.String(nifcloud.ToString(apiSecurityGroup.GroupDescription), sgMetadata),
	}

	for _, rule := range apiSecurityGroup.IpPermissions {

		if nifcloud.ToString(rule.InOut) == "IN" {
			for _, ipRange := range rule.IpRanges {
				sg.IngressRules = append(sg.IngressRules, computing.SecurityGroupRule{
					Metadata:    sgMetadata,
					Description: defsecTypes.String(nifcloud.ToString(rule.Description), sgMetadata),
					CIDR:        defsecTypes.String(nifcloud.ToString(ipRange.CidrIp), sgMetadata),
				})
			}
		}

		if nifcloud.ToString(rule.InOut) == "OUT" {
			for _, ipRange := range rule.IpRanges {
				sg.EgressRules = append(sg.EgressRules, computing.SecurityGroupRule{
					Metadata:    sgMetadata,
					Description: defsecTypes.String(nifcloud.ToString(rule.Description), sgMetadata),
					CIDR:        defsecTypes.String(nifcloud.ToString(ipRange.CidrIp), sgMetadata),
				})
			}
		}

	}

	return sg, nil
}
