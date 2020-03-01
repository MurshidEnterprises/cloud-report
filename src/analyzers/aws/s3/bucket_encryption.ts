import { CheckAnalysisType, ICheckAnalysisResult, IResourceAnalysisResult, SeverityStatus } from "../../../types";
import { BaseAnalyzer } from "../../base";

export class BucketEncryptionAnalyzer extends BaseAnalyzer {

    public analyze(params: any): any {
        const allBucketEncryptions = params.bucket_encryption;
        if (!allBucketEncryptions || allBucketEncryptions.length === 0) {
            return undefined;
        }
        const bucket_encryption: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        bucket_encryption.what = "Are there any buckets without encryption at rest?";
        bucket_encryption.why = "Generally bucket objects should be encrypted at rest";
        bucket_encryption.recommendation = "Recommended to keep objects encrypted to ensure they are secured where they are stored";
        bucket_encryption.benchmark = ['all', 'hippa'];
        const allBucketsAnalysis: IResourceAnalysisResult[] = [];

        for (const bucketName in allBucketEncryptions) {
            const bucketEncryption = allBucketEncryptions[bucketName];
            const bucketAnalysis: IResourceAnalysisResult = {};
            bucketAnalysis.title = "Bucket Encryption"
            bucketAnalysis.resource = { bucketName, bucketEncryption };
            bucketAnalysis.resourceSummary = { name: "Bucket", value: bucketName };
            if (bucketEncryption.ServerSideEncryptionConfiguration) {
                bucketEncryption.ServerSideEncryptionConfiguration.Rules.forEach(rule => {
                    if (rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm === "AES256") {
                        bucketAnalysis.severity = SeverityStatus.Good
                        bucketAnalysis.message = "Bucket objects are encrypted with AES256 encryption";
                        bucketAnalysis.action = "No Action Required";
                    }
                    else if (rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm === "aws:kms") {
                        bucketAnalysis.severity = SeverityStatus.Good;
                        bucketAnalysis.action = "No Action Required";
                        if (rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID.includes("/aws/s3")) {
                            bucketAnalysis.message = "Bucket objects are encrypted with AWS managed KMS keys";
                        }
                        else {
                            bucketAnalysis.message = "Bucket objects are encrypted with customer managed KMS keys";
                        }
                    }
                })
            }
            else {
                bucketAnalysis.severity = SeverityStatus.Warning;
                bucketAnalysis.message = "Bucket objects are not encrypted at rest";
                bucketAnalysis.action = "Encrypt the Bucket objects";
            }
            allBucketsAnalysis.push(bucketAnalysis);
        }
        bucket_encryption.regions = { global: allBucketsAnalysis };
        return { bucket_encryption };
    }
}
