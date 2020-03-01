import * as AWS from "aws-sdk";
import { CollectorUtil, CommonUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";
import { BucketsCollector } from "./buckets";

export class BucketEncryptionCollector extends BaseCollector {
    public collect() {
        return this.listAllBucketEncryption();
    }

    private async listAllBucketEncryption() {
        const s3 = this.getClient("S3", "us-east-1") as AWS.S3;
        const bucketsCollector = new BucketsCollector();
        bucketsCollector.setSession(this.getSession());
        const bucket_encryption = {};
        try {
            const bucketsData = await CollectorUtil.cachedCollect(bucketsCollector);
            for (const bucket of bucketsData.buckets) {
                try {
                    const s3BucketEncryption: AWS.S3.GetBucketEncryptionOutput =
                        await s3.getBucketEncryption({ Bucket: bucket.Name }).promise();
                    bucket_encryption[bucket.Name] = s3BucketEncryption;
                } catch (error) {
                    AWSErrorHandler.handle(error);
                }
                await CommonUtil.wait(200);
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { bucket_encryption };
    }
}