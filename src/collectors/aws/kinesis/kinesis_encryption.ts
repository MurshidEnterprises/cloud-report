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
        const kinesis = this.getClient("Kinesis", "us-east-1") as AWS.Kinesis;
        const kinesisStreamCollector = new KinesisStreamCollector();
        kinesisStreamCollector.setSession(this.getSession());
        const kinesis_encryption = {};
        try {
            const streamData = await CollectorUtil.cachedCollect(kinesisStreamCollector);
            for (const stream of streamData.streams) {
                try {
                    const kinesisStreamData: AWS.Kinesis.DescribeStreamOutput =
                        await kinesis.describeStream({ StreamName: stream }).promise();
                    kinesis_encryption[stream] = kinesisStreamData.StreamDescription;
                } catch (error) {
                    AWSErrorHandler.handle(error);
                }
                await CommonUtil.wait(200);
            }
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
        return { kinesis_encryption };
    }
}