package awssecurity

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3svc "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/devopsproxy/dp/internal/models"
)

// collectS3Buckets lists all S3 buckets in the account and checks each
// bucket's public-access status (GetBucketPolicyStatus) and whether default
// server-side encryption is configured (GetBucketEncryption).
func collectS3Buckets(ctx context.Context, client s3APIClient) ([]models.AWSS3Bucket, error) {
	out, err := client.ListBuckets(ctx, &s3svc.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list S3 buckets: %w", err)
	}

	buckets := make([]models.AWSS3Bucket, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		buckets = append(buckets, models.AWSS3Bucket{
			Name:                     name,
			Public:                   isBucketPublic(ctx, client, name),
			DefaultEncryptionEnabled: isBucketEncryptionEnabled(ctx, client, name),
		})
	}
	return buckets, nil
}

// isBucketPublic returns true only when GetBucketPolicyStatus reports the
// bucket's policy as public (IsPublic == true). Buckets without a bucket
// policy return a NoSuchBucketPolicy error, which is treated as not public.
// All other errors are also treated as not public to avoid false positives.
func isBucketPublic(ctx context.Context, client s3APIClient, name string) bool {
	out, err := client.GetBucketPolicyStatus(ctx, &s3svc.GetBucketPolicyStatusInput{
		Bucket: aws.String(name),
	})
	if err != nil {
		// NoSuchBucketPolicy → no policy configured, not considered public.
		// Any other error: conservative, do not flag.
		return false
	}
	if out.PolicyStatus == nil {
		return false
	}
	return aws.ToBool(out.PolicyStatus.IsPublic)
}

// isBucketEncryptionEnabled returns true when GetBucketEncryption returns a
// valid server-side encryption configuration for the bucket. A missing
// configuration (ServerSideEncryptionConfigurationNotFoundError) or any other
// error is treated as "encryption not configured" (returns false).
func isBucketEncryptionEnabled(ctx context.Context, client s3APIClient, name string) bool {
	_, err := client.GetBucketEncryption(ctx, &s3svc.GetBucketEncryptionInput{
		Bucket: aws.String(name),
	})
	return err == nil
}
