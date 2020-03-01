import * as AWS from "aws-sdk";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class VolumesCollector extends BaseCollector {
    public collect(callback: (err?: Error, data?: any) => void) {
        return this.listAllEBS();
    }

    private async listAllEBS() {
        const serviceName = "EC2";
        const ec2Regions = this.getRegions(serviceName);
        const volumes = {};
        for (const region of ec2Regions) {
            try {
                const ec2 = this.getClient(serviceName, region) as AWS.EC2;
                const EBSData: AWS.EC2.DescribeVolumesResult = await ec2.describeVolumes().promise();
                volumes[region] = EBSData.Volumes;
            } catch (error) {
                AWSErrorHandler.handle(error);
            }
        }
        return { volumes }
    }
}
