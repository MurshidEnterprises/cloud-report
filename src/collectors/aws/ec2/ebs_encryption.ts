import * as AWS from "aws-sdk";
import { CollectorUtil, CommonUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";
import { VolumesCollector } from "./list_ebs";

export class VolumeEncryptionCollector extends BaseCollector {
    public collect() {
        return this.listAllVolumeEncryption();
    }

    private async listAllVolumeEncryption() {
        const volumesCollector = new VolumesCollector();
        volumesCollector.setSession(this.getSession());
        const volumes_encryption = {};
        try {
            const volumeData = await CollectorUtil.cachedCollect(volumesCollector);
            const ec2Regions = this.getRegions("EC2");
            for (const region of ec2Regions) {
                try {
                    volumes_encryption[region] = [];
                    volumeData.volumes[region].forEach(volume => {
                        let obj = {};
                        obj[volume.VolumeId] = {
                            Encrypted: volume.Encrypted,
                            KmsKeyId: volume.KmsKeyId
                        }
                        volumes_encryption[region].push(obj);
                    })
                } catch (error) {
                    AWSErrorHandler.handle(error);
                }
                await CommonUtil.wait(200);
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { volumes_encryption };
    }
}