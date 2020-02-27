import {
    CheckAnalysisType, ICheckAnalysisResult, IDictionary,
    IResourceAnalysisResult, SeverityStatus,
} from "../../../types";
import { BaseAnalyzer } from "../../base";

export class RedshiftEncryptionAnalyzer extends BaseAnalyzer {

    public analyze(params: any, fullReport?: any): any {
        const allClusters = params.redshift_clusters;
        if (!allClusters) {
            return undefined;
        }
        const encryption_redshift_clusters: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        encryption_redshift_clusters.what = "Is encryption enabled for RedShift clusters?";
        encryption_redshift_clusters.why = "Data at rest should always be encrypted";
        encryption_redshift_clusters.recommendation = "Recommended to enable encryption for Redshift Clusters";
        encryption_redshift_clusters.benchmark = ['all', 'hipaa'];
        const allRegionsAnalysis: IDictionary<IResourceAnalysisResult[]> = {};
        for (const region in allClusters) {
            const regionClusters = allClusters[region];
            allRegionsAnalysis[region] = [];
            for (const clusterIdentifier of regionClusters) {
                const cluster_encryption_analysis: IResourceAnalysisResult = {};
                const cluster = clusterIdentifier;
                cluster_encryption_analysis.resource = cluster;
                cluster_encryption_analysis.resourceSummary = {
                    name: "Cluster", value: cluster
                };
                if (cluster.Encrypted) {
                    cluster_encryption_analysis.severity = SeverityStatus.Good;
                    cluster_encryption_analysis.message = "Encryption enabled";
                } else {
                    cluster_encryption_analysis.severity = SeverityStatus.Warning;
                    cluster_encryption_analysis.message = "Encryption not enabled";
                    cluster_encryption_analysis.action = "Enable encryption at rest";
                }
                allRegionsAnalysis[region].push(cluster_encryption_analysis);
            }
        }
        encryption_redshift_clusters.regions = allRegionsAnalysis;
        return { encryption_redshift_clusters };
    }
}
