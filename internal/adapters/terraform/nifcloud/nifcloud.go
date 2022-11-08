package nifcloud

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/nifcloud/computing"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) nifcloud.NIFCLOUD {
	return nifcloud.NIFCLOUD{
		COMPUTING: computing.Adapt(modules),
	}
}
