import * as AWS from "aws-sdk";
import { CollectorUtil, CommonUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";
import { EFSCollector } from "./efs";

export class EFSEncryptionCollector extends BaseCollector {
    public collect() {
        return this.listAllEFSEncryption();
    }

    private async listAllEFSEncryption() {
        const efsCollector = new EFSCollector();
        efsCollector.setSession(this.getSession());
        const efs_encryption = {};
        const efs = await CollectorUtil.cachedCollect(efsCollector);

        try {
            for (const region in efs.efsData) {
                let kms = this.getClient("KMS", region) as AWS.KMS;
                efs_encryption[region] = [];
                for (const fs of efs.efsData[region]) {
                    try {
                        let kmsKey = fs.KmsKeyId;
                        let kmsId = kmsKey.split("/")[kmsKey.split("/").length - 1];
                        let kmsData = await kms.describeKey({KeyId: kmsId}).promise();
                        let keyManager = kmsData.KeyMetadata;
                        let obj = {};
                        
                        obj[fs.FileSystemId] = {
                            Encrypted: fs.Encrypted,
                            KmsKeyId: fs.KmsKeyId,
                            KeyManager: keyManager
                        }
                        efs_encryption[region].push(obj);
                    } catch (error) {
                        AWSErrorHandler.handle(error);
                    }
                    await CommonUtil.wait(200);
                }
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { efs_encryption };
    }
}