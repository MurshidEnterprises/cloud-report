import * as AWS from "aws-sdk";
import { CommonUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class KMSCollector extends BaseCollector {
    public async collect() {
        const serviceName = "KMS";
        const kmsRegions = this.getRegions(serviceName);
        const self = this;
        const keys = {};
        for (const region of kmsRegions) {
            try {
                let fetchPending = true;
                let marker: string | undefined;
                keys[region] = [];
                while (fetchPending) {
                    const kms = self.getClient(serviceName, region) as AWS.KMS;
                    const kmsResponse: AWS.KMS.Types.ListKeysResponse =
                        await kms.listKeys({ Marker: marker }).promise();
                    keys[region] = keys[region].concat(kmsResponse.Keys);
                    marker = kmsResponse.NextMarker;
                    fetchPending = marker !== undefined && marker !== null;
                    await CommonUtil.wait(200);
                }
            } catch (error) {
                AWSErrorHandler.handle(error);
            }
        }
        return { keys };
    }
}
