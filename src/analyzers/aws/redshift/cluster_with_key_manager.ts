import {
    CheckAnalysisType, ICheckAnalysisResult, IDictionary,
    IResourceAnalysisResult, SeverityStatus,
} from "../../../types";
import { BaseAnalyzer } from "../../base";

export class RedshiftCMKEncryptionAnalyzer extends BaseAnalyzer {

    public analyze(params: any, fullReport?: any): any {
        const allClusters = params.cluster_with_key_manager;
        if (!allClusters) {
            return undefined;
        }
        const cmk_encryption_redshift_clusters: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        cmk_encryption_redshift_clusters.what = "Is encryption enabled for RedShift clusters using KMS CMK?";
        cmk_encryption_redshift_clusters.why = "Data at rest should always be encrypted";
        cmk_encryption_redshift_clusters.recommendation = "Recommended to enable encryption for Redshift Clusters";
        cmk_encryption_redshift_clusters.benchmark = ['all', 'hipaa'];
        const allRegionsAnalysis: IDictionary<IResourceAnalysisResult[]> = {};
        for (const region in allClusters) {
            const regionClusters = allClusters[region];
            allRegionsAnalysis[region] = [];
            for (const clusterIdentifier of regionClusters) {
                const cluster_encryption_analysis: IResourceAnalysisResult = {};
                const cluster = clusterIdentifier;
                cluster_encryption_analysis.resource = cluster;
                cluster_encryption_analysis.resourceSummary = {
                    name: "Cluster", value: cluster.ClusterIdentifier
                };
                if (cluster.Encrypted && cluster.KmsKeyWithDescription.KeyMetadata &&
                    (cluster.KmsKeyWithDescription.KeyMetadata.KeyManager !== 'AWS')) {
                    cluster_encryption_analysis.severity = SeverityStatus.Good;
                    cluster_encryption_analysis.message = "Encryption enabled";
                } else {
                    cluster_encryption_analysis.severity = SeverityStatus.Failure;
                    cluster_encryption_analysis.message = "Encryption not enabled using KMS CMK for Redshift cluster";
                    cluster_encryption_analysis.action = "Enable encryption at rest for Redshift cluster using KMS CMK";
                }
                allRegionsAnalysis[region].push(cluster_encryption_analysis);
            }
        }
        cmk_encryption_redshift_clusters.regions = allRegionsAnalysis;
        return { cmk_encryption_redshift_clusters };
    }
}
