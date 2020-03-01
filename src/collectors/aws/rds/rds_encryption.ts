import * as AWS from "aws-sdk";
import { CollectorUtil, CommonUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";
import { RDSInstancesCollector } from "./instances";

export class RDSEncryptionCollector extends BaseCollector {
    public collect() {
        return this.listAllEFSEncryption();
    }

    private async listAllEFSEncryption() {
        const rdsCollector = new RDSInstancesCollector();
        rdsCollector.setSession(this.getSession());
        const rds_encryption = {};
        const rds = await CollectorUtil.cachedCollect(rdsCollector);

        try {
            for (const region in rds.instances) {
                let kms = this.getClient("KMS", region) as AWS.KMS;
                rds_encryption[region] = [];
                for (const instance of rds.instances[region]) {
                    try {
                        let obj = {};
                        if (instance.StorageEncrypted) {
                            let kmsKey = instance.KmsKeyId;
                            let kmsId = kmsKey.split("/")[kmsKey.split("/").length - 1];
                            let kmsData = await kms.describeKey({ KeyId: kmsId }).promise();
                            let keyManager = kmsData.KeyMetadata;

                            obj[instance.DBInstanceIdentifier] = {
                                Encrypted: instance.StorageEncrypted,
                                KmsKeyId: instance.KmsKeyId,
                                KeyManager: keyManager
                            }
                        }
                        else {
                            obj[instance.DBInstanceIdentifier] = {
                                Encrypted: instance.StorageEncrypted
                            }
                        }
                        rds_encryption[region].push(obj);

                    } catch (error) {
                        AWSErrorHandler.handle(error);
                    }
                    await CommonUtil.wait(200);
                }
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { rds_encryption };
    }
}