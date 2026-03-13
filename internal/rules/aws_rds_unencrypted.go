package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSRDSUnencryptedRule flags RDS instances that do not have storage encryption
// enabled. Unencrypted RDS storage exposes database files, automated backups,
// and read replicas to unauthorised access at the storage layer.
type AWSRDSUnencryptedRule struct{}

func (r AWSRDSUnencryptedRule) ID() string   { return "RDS_UNENCRYPTED" }
func (r AWSRDSUnencryptedRule) Name() string { return "RDS Instance Without Storage Encryption" }

// Evaluate returns one CRITICAL finding per RDS instance where
// StorageEncrypted == false. CRITICAL severity reflects the sensitivity of
// database workloads compared to general EBS volumes.
func (r AWSRDSUnencryptedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	var findings []models.Finding
	for _, inst := range ctx.RegionData.RDSInstances {
		if inst.StorageEncrypted {
			continue
		}
		findings = append(findings, models.Finding{
			ID:             fmt.Sprintf("%s-%s", r.ID(), inst.DBInstanceID),
			RuleID:         r.ID(),
			ResourceID:     inst.DBInstanceID,
			ResourceType:   models.ResourceAWSRDS,
			Region:         ctx.RegionData.Region,
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityCritical,
			Explanation:    fmt.Sprintf("RDS instance %s does not have storage encryption enabled.", inst.DBInstanceID),
			Recommendation: "Enable storage encryption for RDS instances. Encryption must be set at creation time; to encrypt an existing instance, take a snapshot, copy it with encryption enabled, and restore from that snapshot.",
			DetectedAt:     time.Now().UTC(),
			Metadata: map[string]any{
				"engine":            inst.Engine,
				"db_instance_class": inst.DBInstanceClass,
				"status":            inst.Status,
			},
		})
	}
	return findings
}
