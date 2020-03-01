import { CheckAnalysisType, ICheckAnalysisResult, IDictionary, IResourceAnalysisResult, SeverityStatus } from "../../../types";
import { BaseAnalyzer } from "../../base";

export class StreamEncryptionAnalyzer extends BaseAnalyzer {

    public analyze(params: any): any {
        const allStreamEncryptions = params.kinesis_encryption;
        if (!allStreamEncryptions || allStreamEncryptions.length === 0) {
            return undefined;
        }
        const stream_encryption: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        stream_encryption.what = "Are there any streams without encryption at rest?";
        stream_encryption.why = "Generally kinesis streams should be encrypted at rest";
        stream_encryption.recommendation = "Recommended to keep kinesis streams encrypted to ensure they are secured where they are stored";
        stream_encryption.benchmark = ['all', 'hippa'];
        const allStreamsAnalysis: IDictionary<IResourceAnalysisResult[]> = {};

        for (const region in allStreamEncryptions) {
            for (const stream of allStreamEncryptions[region]) {
                for (const streamName in stream) {
                    allStreamsAnalysis[region] = [];
                    const streamEncryption = stream[streamName];
                    const streamAnalysis: IResourceAnalysisResult = {};
                    streamAnalysis.title = "Stream Encryption"
                    streamAnalysis.resource = { streamName, streamEncryption };
                    streamAnalysis.resourceSummary = { name: "Stream", value: streamName };
                    if (streamEncryption.EncryptionType === 'KMS' && streamEncryption.KeyId.includes("alias/aws/kinesis")) {
                        streamAnalysis.severity = SeverityStatus.Good
                        streamAnalysis.message = "Kinesis Streams are encrypted with KMS encryption where master key is owned by Kinesis Data Streams";
                        streamAnalysis.action = "No Action Required";
                    }
                    else if (streamEncryption.EncryptionType === 'KMS') {
                        streamAnalysis.severity = SeverityStatus.Good
                        streamAnalysis.message = "Kinesis Streams are encrypted with customr managed KMS encryption";
                        streamAnalysis.action = "No Action Required";
                    }
                    else if (streamEncryption.EncryptionType === 'NONE') {
                        streamAnalysis.severity = SeverityStatus.Warning;
                        streamAnalysis.message = "Kinesis Streams are not encrypted at rest";
                        streamAnalysis.action = "Encrypt the Kinesis Streams";
                    }
                    allStreamsAnalysis[region].push(streamAnalysis);
                }
            }
        }
        stream_encryption.regions = allStreamsAnalysis ;
        return { stream_encryption };
    }
}
