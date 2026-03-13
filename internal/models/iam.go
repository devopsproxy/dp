package models

// CloudResourceType identifies the kind of AWS cloud resource that an IAM role
// can access. Used by the asset graph's cloud reachability enrichment (Phase 12).
type CloudResourceType string

const (
	// CloudResourceTypeS3Bucket is an Amazon S3 bucket.
	CloudResourceTypeS3Bucket CloudResourceType = "S3Bucket"

	// CloudResourceTypeSecretsManagerSecret is an AWS Secrets Manager secret.
	CloudResourceTypeSecretsManagerSecret CloudResourceType = "SecretsManagerSecret"

	// CloudResourceTypeDynamoDBTable is an Amazon DynamoDB table.
	CloudResourceTypeDynamoDBTable CloudResourceType = "DynamoDBTable"

	// CloudResourceTypeKMSKey is an AWS KMS key.
	CloudResourceTypeKMSKey CloudResourceType = "KMSKey"

	// CloudResourceTypeSSMParameter is an AWS Systems Manager Parameter Store entry.
	CloudResourceTypeSSMParameter CloudResourceType = "SSMParameter"
)

// AssumableRole describes an IAM role that can be assumed by another role via
// sts:AssumeRole, as detected from the source role's attached policies.
// Used by graph.EnrichWithAssumeRoleEdges to add ASSUME_ROLE edges (Phase 16.1).
type AssumableRole struct {
	// ARN is the full Amazon Resource Name of the target role to be assumed.
	ARN string

	// RoleName is the short role name extracted from ARN (e.g. "admin-role").
	RoleName string
}

// RoleCloudAccess describes a single AWS resource that an IAM role has
// permission to access, as resolved from the role's attached policies.
// It is produced by internal/providers/aws/iam.ResolveRoleResourceAccess
// and consumed by internal/graph.EnrichWithCloudAccess.
type RoleCloudAccess struct {
	// ResourceType classifies the AWS resource.
	ResourceType CloudResourceType

	// ResourceName is the short resource name (bucket name, table name, key ID, etc.).
	ResourceName string

	// ARN is the full Amazon Resource Name. May be empty for wildcard-derived entries.
	ARN string

	// Sensitivity is the sensitivity classification for this resource, set by
	// internal/providers/aws/sensitivity.ClassifyResource before graph enrichment.
	Sensitivity SensitivityLevel
}
