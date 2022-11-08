package computing

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) computing.COMPUTING {

	sgAdapter := sgAdapter{sgRuleIDs: modules.GetChildResourceIDMapByType("nifcloud_security_group_rule")}

	return computing.COMPUTING{
		SecurityGroups: sgAdapter.adaptSecurityGroups(modules),
	}
}
