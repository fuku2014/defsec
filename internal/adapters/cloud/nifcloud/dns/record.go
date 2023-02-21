package dns

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/dns"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/nifcloud/nifcloud-sdk-go/nifcloud"
	dnsClient "github.com/nifcloud/nifcloud-sdk-go/service/dns"
	"github.com/nifcloud/nifcloud-sdk-go/service/dns/types"
)

func (a *adapter) getRecords() (records []dns.Record, err error) {

	a.Tracker().SetServiceLabel("Discovering records...")

	var recordSets []types.ResourceRecordSets

	zones, err := a.client.ListHostedZones(a.Context(), nil)
	if err != nil {
		return nil, err
	}

	for _, zone := range zones.HostedZones {
		output, err := a.client.ListResourceRecordSets(a.Context(), &dnsClient.ListResourceRecordSetsInput{ZoneID: zone.Name})
		if err != nil {
			return nil, err
		}
		for _, recordSet := range output.ResourceRecordSets {
			recordSets = append(recordSets, recordSet)
		}
	}

	a.Tracker().SetTotalResources(len(recordSets))
	a.Tracker().SetServiceLabel("Adapting records...")
	return concurrency.Adapt(recordSets, a.RootAdapter, a.adaptRecord), nil
}

func (a *adapter) adaptRecord(recordSet types.ResourceRecordSets) (*dns.Record, error) {
	recordMetadata := a.CreateMetadata("record/" + nifcloud.ToString(recordSet.Name))

	record := &dns.Record{
		Metadata: recordMetadata,
		Type:     defsecTypes.String(nifcloud.ToString(recordSet.Type), recordMetadata),
		Record:   defsecTypes.String(nifcloud.ToString(recordSet.ResourceRecords[0].Value), recordMetadata),
	}
	return record, nil
}
