import * as AWS from "aws-sdk";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class KinesisStreamCollector extends BaseCollector {
    public collect(callback: (err?: Error, data?: any) => void) {
        return this.listAllKinesisStream();
    }

    private async listAllKinesisStream() {
        try {
            const kinesis = this.getClient("Kinesis", "us-east-1") as AWS.Kinesis;
            const kinesisStreamData: AWS.Kinesis.ListStreamsOutput = await kinesis.listStreams().promise();
            const streams = kinesisStreamData.StreamNames;
            return { streams };
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
    }
}
