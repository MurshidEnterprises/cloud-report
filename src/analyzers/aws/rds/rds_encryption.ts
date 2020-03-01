import { CheckAnalysisType, ICheckAnalysisResult, IDictionary, IResourceAnalysisResult, SeverityStatus } from "../../../types";
import { BaseAnalyzer } from "../../base";

export class RDSEncryptionAnalyzer extends BaseAnalyzer {

    public analyze(params: any): any {
        const allRDSEncryptions = params.rds_encryption;
        if (!allRDSEncryptions || allRDSEncryptions.length === 0) {
            return undefined;
        }
        const rds_encryption: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        rds_encryption.what = "Are there any rds instances without encryption at rest?";
        rds_encryption.why = "Generally rds instances should be encrypted at rest";
        rds_encryption.recommendation = "Recommended to keep rds instances data encrypted to ensure they are secured where they are stored";
        rds_encryption.benchmark = ['all', 'hippa'];
        const allRDSAnalysis: IDictionary<IResourceAnalysisResult[]> = {};

        for (const region in allRDSEncryptions) {
            for (const rdsInstance of allRDSEncryptions[region]) {
                for (const rdsName in rdsInstance) {
                    allRDSAnalysis[region] = [];
                    const rdsEncryption = rdsInstance[rdsName];
                    const rdsAnalysis: IResourceAnalysisResult = {};
                    rdsAnalysis.title = "RDS Encryption"
                    rdsAnalysis.resource = { rdsName, rdsEncryption };
                    rdsAnalysis.resourceSummary = { name: "RDS", value: rdsName };
                    if (rdsEncryption.Encrypted === true && rdsEncryption.KeyManager.KeyManager === 'AWS') {
                        rdsAnalysis.severity = SeverityStatus.Good
                        rdsAnalysis.message = "RDS instance is encrypted with AWS Managed KMS encryption";
                        rdsAnalysis.action = "No Action Required";
                    }
                    else if (rdsEncryption.Encrypted === true) {
                        rdsAnalysis.severity = SeverityStatus.Good
                        rdsAnalysis.message = "RDS instance is encrypted with customr managed KMS encryption";
                        rdsAnalysis.action = "No Action Required";
                    }
                    else if (rdsEncryption.EncryptionType === false) {
                        rdsAnalysis.severity = SeverityStatus.Warning;
                        rdsAnalysis.message = "RDS instance is not encrypted at rest";
                        rdsAnalysis.action = "Encrypt the RDS Instance";
                    }
                    allRDSAnalysis[region].push(rdsAnalysis);
                }
            }
        }
        rds_encryption.regions = allRDSAnalysis ;
        return { efs_encryption: rds_encryption };
    }
}
