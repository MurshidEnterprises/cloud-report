import * as AWS from "aws-sdk";
import { CollectorUtil, CommonUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";
import { KinesisStreamCollector } from "./kinesis";

export class StreamEncryptionCollector extends BaseCollector {
    public collect() {
        return this.listAllStreamEncryption();
    }

    private async listAllStreamEncryption() {
        const serviceName = "Kinesis";
        const kinesisStreamCollector = new KinesisStreamCollector();
        kinesisStreamCollector.setSession(this.getSession());
        const kinesis_encryption = {};
        const streamData = await CollectorUtil.cachedCollect(kinesisStreamCollector);

        try {
            for (const region in streamData.streams) {
                kinesis_encryption[region] = [];
                const kinesis = this.getClient(serviceName, region) as AWS.Kinesis;
                for (const stream of streamData.streams[region]) {
                    try {
                        const kinesisStreamData: AWS.Kinesis.DescribeStreamOutput =
                            await kinesis.describeStream({ StreamName: stream }).promise();
                        let obj = {};
                        obj[stream] = kinesisStreamData.StreamDescription;
                        kinesis_encryption[region].push(obj);
                    } catch (error) {
                        AWSErrorHandler.handle(error);
                    }
                    await CommonUtil.wait(200);
                }
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { kinesis_encryption };
    }
}