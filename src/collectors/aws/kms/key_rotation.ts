import * as AWS from "aws-sdk";
import { KMSCollector, KeyDescriptionCollector } from '.'
import { CommonUtil, CollectorUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class KeyRotationCollector extends BaseCollector {
    public async collect() {
        const serviceName = "KMS";
        const kmsRegions = this.getRegions(serviceName);
        const self = this;
        const key_rotation = {};

        const kmsCollector = new KMSCollector();
        kmsCollector.setSession(self.getSession());

        try {
            const keyData = await CollectorUtil.cachedCollect(kmsCollector);
            for (const region of kmsRegions) {
                key_rotation[region] = [];
                const regionKeys = keyData.keys[region];
                const kms = self.getClient(serviceName, region) as AWS.KMS;
                for (let key of regionKeys) {
                    const kmsResponse: AWS.KMS.Types.GetKeyRotationStatusResponse =
                        await kms.getKeyRotationStatus({ KeyId: key.KeyId }).promise();
                    key.KeyRotationEnabled = kmsResponse.KeyRotationEnabled;
                    key_rotation[region].push(key);
                }
                await CommonUtil.wait(200);
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { key_rotation };
    }
}
