import * as AWS from "aws-sdk";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

export class KinesisStreamCollector extends BaseCollector {
    public collect(callback: (err?: Error, data?: any) => void) {
        return this.listAllKinesisStream();
    }

    private async listAllKinesisStream() {
        try {
            const serviceName = "Kinesis";
            const kinesisRegions = this.getRegions(serviceName);
            const streams = {};
            for (const region of kinesisRegions) {
                const kinesis = this.getClient(serviceName, region) as AWS.Kinesis;
                const kinesisStreamData: AWS.Kinesis.ListStreamsOutput = await kinesis.listStreams().promise();
                streams[region] = kinesisStreamData.StreamNames;
            }
            return { streams };
        } catch (error) {
            AWSErrorHandler.handle(error);
        }
    }
}
