import * as AWS from "aws-sdk";
import { KMSCollector } from '.'
import { CollectorUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class KeyDescriptionCollector extends BaseCollector {
    public async collect() {
        const serviceName = "KMS";
        const kmsRegions = this.getRegions(serviceName);
        const self = this;
        const keys_with_description = {};

        const kmsCollector = new KMSCollector();
        kmsCollector.setSession(self.getSession());

        try {
            const keyData = await CollectorUtil.cachedCollect(kmsCollector);
            for (const region of kmsRegions) {
                const kms = self.getClient(serviceName, region) as AWS.KMS;
                keys_with_description[region] = [];
                const regionKeys = keyData.keys[region]? keyData.keys[region]: [];
                for (let key of regionKeys) {
                    const keyDescription: AWS.KMS.Types.DescribeKeyResponse = await kms.describeKey({KeyId: key.KeyId}).promise();
                    key.KeyMetadata = keyDescription.KeyMetadata;
                    keys_with_description[region].push(key)
                }
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { keys_with_description };
    }
}
