import {
    CheckAnalysisType, ICheckAnalysisResult, IDictionary,
    IResourceAnalysisResult, SeverityStatus,
} from "../../../types";
import { ResourceUtil } from "../../../utils";
import { BaseAnalyzer } from "../../base";

export class DescribeMetricsForAlarmsAnalyzer extends BaseAnalyzer {

    public analyze(params: any, fullReport?: any): any {
        const metrics: any[] = params.metrics;
        if (!metrics) {
            return undefined;
        }
        const allMetrics: any[] = fullReport["aws.cloudwatch"].metrics;

        const describe_metrics_for_alarms: ICheckAnalysisResult = { type: CheckAnalysisType.Security };
        describe_metrics_for_alarms.what = "Is a log metric filter and alarm exist for defined changes in your AWS Infra?";
        describe_metrics_for_alarms.why = "Ensure there is an Amazon CloudWatch alarm created and configured in your AWS account to track the predefined changes.";
        describe_metrics_for_alarms.recommendation = "Recommended to create log metric filter for the defined metric.";
        describe_metrics_for_alarms.benchmark = ['all', 'hipaa'];
        const allRegionsAnalysis: IDictionary<IResourceAnalysisResult[]> = {};
        for (const region in allMetrics) {
            const regionAlarms = allMetrics[region] || [];
            allRegionsAnalysis[region] = [];
            for (const metric of regionAlarms) {
                const metricAnalysis: IResourceAnalysisResult = {};
                metricAnalysis.resource = { metric};
                metricAnalysis.resourceSummary = {
                    name : "metricName",
                    value : metric.MetricName
                }
                if (metric.data.length){
                    metricAnalysis.severity = SeverityStatus.Good;
                    metricAnalysis.message = "Log metrics are enabled";
                }
                else {
                    metricAnalysis.severity = SeverityStatus.Failure;
                    metricAnalysis.message = "Log metrics are enabled";
                    metricAnalysis.action = "Create Log metrics for the identified metric";                    
                }
                allRegionsAnalysis[region].push(metricAnalysis);
            }
        }
        describe_metrics_for_alarms.regions = allRegionsAnalysis;
        return { describe_metrics_for_alarms };
    }

}
