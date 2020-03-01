import { CheckAnalysisType, ICheckAnalysisResult, IDictionary, IResourceAnalysisResult, SeverityStatus } from "../../../types";
import { BaseAnalyzer } from "../../base";

export class VolumeEncryptionAnalyzer extends BaseAnalyzer {

    public analyze(params: any): any {
        const allVolumeEncryptions = params.volumes_encryption;
        if (!allVolumeEncryptions || allVolumeEncryptions.length === 0) {
            return undefined;
        }
        const volume_encryption: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        volume_encryption.what = "Are there any volumes without encryption at rest?";
        volume_encryption.why = "Generally EBS volumes should be encrypted at rest";
        volume_encryption.recommendation = "Recommended to keep volumes encrypted to ensure they are secured where they are stored";
        volume_encryption.benchmark = ['all', 'hippa'];
        const allRegionsAnalysis: IDictionary<IResourceAnalysisResult[]> = {};

        for (const region in allVolumeEncryptions) {
            allRegionsAnalysis[region] = [];
            const volumes = allVolumeEncryptions[region];
            volumes.forEach(volumeEncryption => {
                for (const volumeId in volumeEncryption) {
                    const volumeAnalysis: IResourceAnalysisResult = {};
                    volumeAnalysis.title = "Volume Encryption"
                    volumeAnalysis.resource = { volumeId, volumeEncryption };
                    volumeAnalysis.resourceSummary = { name: "Volume", value: region };
                    if (volumeEncryption[volumeId].Encrypted === true && volumeEncryption[volumeId].KmsKeyId.includes("alias/aws/ebs")) {
                        volumeAnalysis.severity = SeverityStatus.Good
                        volumeAnalysis.message = "EBS volumes are encrypted with aws managed KMS encryption";
                        volumeAnalysis.action = "No Action Required";
                    }
                    else if (volumeEncryption[volumeId].Encrypted === true) {
                        volumeAnalysis.severity = SeverityStatus.Good
                        volumeAnalysis.message = "EBS volumes are encrypted with customr managed KMS encryption";
                        volumeAnalysis.action = "No Action Required";
                    }
                    else if (volumeEncryption[volumeId].Encrypted === false) {
                        volumeAnalysis.severity = SeverityStatus.Warning;
                        volumeAnalysis.message = "EBS volumes are not encrypted at rest";
                        volumeAnalysis.action = "Encrypt the EBS volumes";
                    }
                    allRegionsAnalysis[region].push(volumeAnalysis);
                }
            })
        }
        volume_encryption.regions = allRegionsAnalysis
        return { volume_encryption };
    }
}
