import * as AWS from "aws-sdk";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class EFSCollector extends BaseCollector {
    public collect(callback: (err?: Error, data?: any) => void) {
        return this.listAllEFS();
    }

    private async listAllEFS() {
        try {
            const serviceName = "EFS";
            const efsRegions = this.getRegions(serviceName);
            const efsData = {};
            for (const region of efsRegions) {
                const efs = this.getClient(serviceName, region) as AWS.EFS;
                const efsResponse: AWS.EFS.DescribeFileSystemsResponse = await efs.describeFileSystems().promise();
                efsData[region] = efsResponse.FileSystems;
            }
            return { efsData };
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
    }
}
