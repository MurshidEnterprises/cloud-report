import {
    CheckAnalysisType, ICheckAnalysisResult, IDictionary,
    IResourceAnalysisResult, SeverityStatus,
} from "../../../types";
import { BaseAnalyzer } from "../../base";

export class CloudTrailsCMKEncryptionAnalyzer extends BaseAnalyzer {

    public analyze(params: any, fullReport?: any): any {
        const allTrails = params.trail_with_key_aliases;
        if (!allTrails) {
            return undefined;
        }
        const cloud_trails_cmk_encryption_at_rest: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        cloud_trails_cmk_encryption_at_rest.what = "Are Cloud trails encrypted using KMS CMK at rest?";
        cloud_trails_cmk_encryption_at_rest.why = "Critical data should always be encrypted at rest";
        cloud_trails_cmk_encryption_at_rest.recommendation = "Recommended to enable KMS CMK encryption at rest for CloudTrails";
        cloud_trails_cmk_encryption_at_rest.benchmark = ['all', 'hipaa'];
        const allRegionsAnalysis: IDictionary<IResourceAnalysisResult[]> = {};
        for (const region in allTrails) {
            const regionTrails = allTrails[region];
            allRegionsAnalysis[region] = [];
            for (const trail of regionTrails) {
                const trail_analysis: IResourceAnalysisResult = {};
                trail_analysis.resource = trail;
                trail_analysis.resourceSummary = {
                    name: "CloudTrail", value: trail.Name,
                };
                if (trail.KmsKeyWithDescription && trail.KmsKeyWithDescription.KeyMetadata &&
                    (trail.KmsKeyWithDescription.KeyMetadata.KeyManager !== 'AWS')) {
                    trail_analysis.severity = SeverityStatus.Good;
                    trail_analysis.message = "Encryption enabled";
                } else {
                    trail_analysis.severity = SeverityStatus.Failure;
                    trail_analysis.message = "Encryption not enabled using CMK";
                    trail_analysis.action = "Enable encryption at rest using KMS CMK";
                }
                allRegionsAnalysis[region].push(trail_analysis);
            }
        }
        cloud_trails_cmk_encryption_at_rest.regions = allRegionsAnalysis;
        return { cloud_trails_cmk_encryption_at_rest };
    }
}
