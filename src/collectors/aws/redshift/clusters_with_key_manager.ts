import * as AWS from "aws-sdk";
import { KeyDescriptionCollector } from '../kms'
import { RedshiftClustersCollector } from '.'
import { CommonUtil, CollectorUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class ClusterKeyAliasCollector extends BaseCollector {
    public async collect() {
        const serviceName = "Redshift";
        const redshiftRegions = this.getRegions(serviceName);
        const self = this;
        const cluster_with_key_manager = {};

        const kmsCollector = new KeyDescriptionCollector();
        kmsCollector.setSession(self.getSession());

        const redshiftCollector = new RedshiftClustersCollector();
        redshiftCollector.setSession(self.getSession());

        try {
            const keyData = await CollectorUtil.cachedCollect(kmsCollector);
            const redshiftData = await CollectorUtil.cachedCollect(redshiftCollector);
            for (const region of redshiftRegions) {
                cluster_with_key_manager[region] = [];
                const regionClusters = redshiftData.clusters[region];
                const regionKeys = keyData.keys_with_description[region] ? keyData.keys_with_description[region] : [];
                for (let cluster of regionClusters) {
                    if (cluster.Encrypted && cluster.KmsKeyId) {
                        const KmsKeyWithDescription = regionKeys.find(key => key.KeyArn === cluster.KmsKeyId);
                        cluster.KmsKeyWithDescription = KmsKeyWithDescription;
                    }
                    cluster_with_key_manager[region].push(cluster);
                }
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { cluster_with_key_manager };
    }
}
