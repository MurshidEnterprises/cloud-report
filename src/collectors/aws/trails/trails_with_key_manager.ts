import * as AWS from "aws-sdk";
import { KeyDescriptionCollector } from '../kms'
import { CloudTrailsCollector } from '.'
import { CommonUtil, CollectorUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class TrailKeyAliasCollector extends BaseCollector {
    public async collect() {
        const serviceName = "CloudTrail";
        const cloudTrailRegions = this.getRegions(serviceName);
        const self = this;
        const trail_with_key_manager = {};

        const kmsCollector = new KeyDescriptionCollector();
        kmsCollector.setSession(self.getSession());

        const trailCollector = new CloudTrailsCollector();
        trailCollector.setSession(self.getSession());

        try {
            const keyData = await CollectorUtil.cachedCollect(kmsCollector);
            const trailData = await CollectorUtil.cachedCollect(trailCollector);
            for (const region of cloudTrailRegions) {
                trail_with_key_manager[region] = [];
                const regionTrails = trailData.cloud_trails[region] ? trailData.cloud_trails[region] : [];
                const regionKeys = keyData.keys_with_description[region] ? keyData.keys_with_description[region] : [];
                for (let trail of regionTrails) {
                    if (trail.KmsKeyId) {
                        const KmsKeyWithDescription = regionKeys.find(key => trail.KmsKeyId === key.KeyArn);
                        trail.KmsKeyWithDescription = KmsKeyWithDescription;
                    }
                    trail_with_key_manager[region].push(trail);
                }
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { trail_with_key_manager };
    }
}
