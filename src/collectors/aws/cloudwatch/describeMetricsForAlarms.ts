import * as AWS from "aws-sdk";
import { CommonUtil } from "../../../utils";
import { AWSErrorHandler } from "../../../utils/aws";
import { BaseCollector } from "../../base";

import { IDictionary } from "../../../types";

import { DefinedMetrics } from "./metrics";

export class MetricCollector extends BaseCollector {
  private context: IDictionary<any> = {};
  public getContext() {
    return this.context;
  }

  public collect(callback: (err?: Error, data?: any) => void) {
    return this.checkAlarmForMetrics();
  }

  private async checkAlarmForMetrics()  {
    const self = this;
    const serviceName = "CloudWatch";
    const CloudWatchRegions = self.getRegions(serviceName);
    const metrics = {};
    for (const region of CloudWatchRegions) {
      try {
        const CloudWatchService = self.getClient(
          serviceName,
          region
        ) as AWS.CloudWatch;
        metrics[region] = [];
        this.context[region] = region;
        for (const eachMetric of DefinedMetrics){
          let params = {
            MetricName: eachMetric.metricName,
            Namespace : eachMetric.nameSpace
          }
          let metricInfo = params 
          const alarmsResponse: AWS.CloudWatch.Types.DescribeAlarmsForMetricOutput = await CloudWatchService.describeAlarmsForMetric(params).promise();
            if (alarmsResponse.MetricAlarms) {
                metricInfo['data'] =  alarmsResponse.MetricAlarms
            }
            else {
                metricInfo['data'] = []
            }
            metrics[region] = metrics[region].concat(metricInfo);
        }
      } catch (error) {
        AWSErrorHandler.handle(error);
        continue;
      }    
    }   
    return { metrics }; 
  }
}
