import { CheckAnalysisType, ICheckAnalysisResult, IDictionary, IResourceAnalysisResult, SeverityStatus } from "../../../types";
import { BaseAnalyzer } from "../../base";

export class EFSEncryptionAnalyzer extends BaseAnalyzer {

    public analyze(params: any): any {
        const allEFSEncryptions = params.efs_encryption;
        if (!allEFSEncryptions || allEFSEncryptions.length === 0) {
            return undefined;
        }
        const efs_encryption: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        efs_encryption.what = "Are there any efs without encryption at rest?";
        efs_encryption.why = "Generally efs should be encrypted at rest";
        efs_encryption.recommendation = "Recommended to keep efs encrypted to ensure they are secured where they are stored";
        efs_encryption.benchmark = ['all', 'hippa'];
        const allEFSAnalysis: IDictionary<IResourceAnalysisResult[]> = {};

        for (const region in allEFSEncryptions) {
            for (const fs of allEFSEncryptions[region]) {
                for (const fsName in fs) {
                    allEFSAnalysis[region] = [];
                    const efsEncryption = fs[fsName];
                    const efsAnalysis: IResourceAnalysisResult = {};
                    efsAnalysis.title = "EFS Encryption"
                    efsAnalysis.resource = { fsName, efsEncryption };
                    efsAnalysis.resourceSummary = { name: "EFS", value: fsName };
                    if (efsEncryption.Encrypted === true && efsEncryption.KeyManager.KeyManager === 'AWS') {
                        efsAnalysis.severity = SeverityStatus.Good
                        efsAnalysis.message = "EFS are encrypted with AWS Managed KMS encryption";
                        efsAnalysis.action = "No Action Required";
                    }
                    else if (efsEncryption.Encrypted === true) {
                        efsAnalysis.severity = SeverityStatus.Good
                        efsAnalysis.message = "EFS are encrypted with customr managed KMS encryption";
                        efsAnalysis.action = "No Action Required";
                    }
                    else if (efsEncryption.EncryptionType === false) {
                        efsAnalysis.severity = SeverityStatus.Warning;
                        efsAnalysis.message = "EFS are not encrypted at rest";
                        efsAnalysis.action = "Encrypt the EFS";
                    }
                    allEFSAnalysis[region].push(efsAnalysis);
                }
            }
        }
        efs_encryption.regions = allEFSAnalysis ;
        return { efs_encryption };
    }
}
