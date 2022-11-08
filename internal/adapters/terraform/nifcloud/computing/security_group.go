package computing

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/computing"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type sgAdapter struct {
	sgRuleIDs terraform.ResourceIDResolutions
}

func (a *sgAdapter) adaptSecurityGroups(modules terraform.Modules) []computing.SecurityGroup {
	var securityGroups []computing.SecurityGroup
	for _, resource := range modules.GetResourcesByType("nifcloud_security_group") {
		securityGroups = append(securityGroups, a.adaptSecurityGroup(resource, modules))
	}
	orphanResources := modules.GetResourceByIDs(a.sgRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := computing.SecurityGroup{
			Metadata:     defsecTypes.NewUnmanagedMetadata(),
			Description:  defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
			IngressRules: nil,
			EgressRules:  nil,
		}
		for _, sgRule := range orphanResources {
			if sgRule.GetAttribute("type").Equals("IN") {
				orphanage.IngressRules = append(orphanage.IngressRules, adaptSGRule(sgRule, modules))
			} else if sgRule.GetAttribute("type").Equals("OUT") {
				orphanage.EgressRules = append(orphanage.EgressRules, adaptSGRule(sgRule, modules))
			}
		}
		securityGroups = append(securityGroups, orphanage)
	}

	return securityGroups
}

func (a *sgAdapter) adaptSecurityGroup(resource *terraform.Block, module terraform.Modules) computing.SecurityGroup {
	var ingressRules []computing.SecurityGroupRule
	var egressRules []computing.SecurityGroupRule

	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("", resource)

	ingressBlocks := resource.GetBlocks("IN")
	for _, ingressBlock := range ingressBlocks {
		ingressRules = append(ingressRules, adaptSGRule(ingressBlock, module))
	}

	egressBlocks := resource.GetBlocks("OUT")
	for _, egressBlock := range egressBlocks {
		egressRules = append(egressRules, adaptSGRule(egressBlock, module))
	}

	rulesBlocks := module.GetReferencingResources(resource, "nifcloud_security_group_rule", "group_name")
	for _, ruleBlock := range rulesBlocks {
		a.sgRuleIDs.Resolve(ruleBlock.ID())
		if ruleBlock.GetAttribute("type").Equals("IN") {
			ingressRules = append(ingressRules, adaptSGRule(ruleBlock, module))
		} else if ruleBlock.GetAttribute("type").Equals("OUT") {
			egressRules = append(egressRules, adaptSGRule(ruleBlock, module))
		}
	}

	return computing.SecurityGroup{
		Metadata:     resource.GetMetadata(),
		Description:  descriptionVal,
		IngressRules: ingressRules,
		EgressRules:  egressRules,
	}
}

func adaptSGRule(resource *terraform.Block, modules terraform.Modules) computing.SecurityGroupRule {
	ruleDescAttr := resource.GetAttribute("description")
	ruleDescVal := ruleDescAttr.AsStringValueOrDefault("", resource)

	cidrAttr := resource.GetAttribute("cidr_ip")
	cidrVal := cidrAttr.AsStringValueOrDefault("", resource)

	return computing.SecurityGroupRule{
		Metadata:    resource.GetMetadata(),
		Description: ruleDescVal,
		CIDR:        cidrVal,
	}
}
