import {
    CheckAnalysisType, ICheckAnalysisResult, IDictionary,
    IResourceAnalysisResult, SeverityStatus,
} from "../../../types";
import { BaseAnalyzer } from "../../base";

export class KMSKeyRotationAnalyzer extends BaseAnalyzer {

    public analyze(params: any, fullReport?: any): any {
        const allKeys = params.key_rotation;
        if (!allKeys) {
            return undefined;
        }
        const key_rotation_cmk: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        key_rotation_cmk.what = "Is key rotation enabled for CMK keys?";
        key_rotation_cmk.why = "Key rotation should be enabled for CMK keys";
        key_rotation_cmk.recommendation = "Recommended to enable key rotation for CMK keys";
        key_rotation_cmk.benchmark = ['all', 'hipaa'];
        const allRegionsAnalysis: IDictionary<IResourceAnalysisResult[]> = {};
        for (const region in allKeys) {
            const regionKeys = allKeys[region];
            allRegionsAnalysis[region] = [];
            for (const key of regionKeys) {
                const key_rotation_analysis: IResourceAnalysisResult = {};
                key_rotation_analysis.resource = key;
                key_rotation_analysis.resourceSummary = {
                    name: "Key", value: key.KeyArn
                };
                if (key.KeyRotationEnabled) {
                    key_rotation_analysis.severity = SeverityStatus.Good;
                    key_rotation_analysis.message = "Key Rotation enabled";
                } else {
                    key_rotation_analysis.severity = SeverityStatus.Warning;
                    key_rotation_analysis.message = "Key Rotation not enabled";
                    key_rotation_analysis.action = "Enable Key Rotation for customer managed keys";
                }
                allRegionsAnalysis[region].push(key_rotation_analysis);
            }
        }
        key_rotation_cmk.regions = allRegionsAnalysis;
        return { key_rotation_cmk };
    }
}
