<p align="center"> <img src="https://avatars.githubusercontent.com/u/145441379?s=200&v=4" width="130" height="130"></p>


<h1 align="center">
    Control Tower inspector
</h1>

<p align="center" style="font-size: 1.2rem;"> 
    CloudFormation Template for inspector.
</p>

<p align="center">
<a href="LICENSE">
  <img src="https://img.shields.io/badge/License-APACHE-blue.svg" alt="Licence">
</a>
<a href="https://github.com/aws-controltower-examples/aws-control-tower-securityhub-enabler/actions/workflows/cf-lint.yml">
  <img src="https://github.com/aws-controltower-examples/aws-control-tower-securityhub-enabler/actions/workflows/cf-lint.yml/badge.svg" alt="tfsec">
</a>



</p>
<p align="center">

<a href='https://facebook.com/sharer/sharer.php?u=https://github.com/aws-controltower-examples/aws-control-tower-inspector'>
  <img title="Share on Facebook" src="https://user-images.githubusercontent.com/50652676/62817743-4f64cb80-bb59-11e9-90c7-b057252ded50.png" />
</a>
<a href='https://www.linkedin.com/shareArticle?mini=true&title=AWS+Control+Tower+inspector+Enabler&url=https://github.com/aws-controltower-examples/aws-control-tower-inspector-enabler'>
  <img title="Share on LinkedIn" src="https://user-images.githubusercontent.com/50652676/62817742-4e339e80-bb59-11e9-87b9-a1f68cae1049.png" />
</a>
<a href='https://twitter.com/intent/tweet/?text=AWS+Control+Tower+inspector+Enabler&url=https://github.com/aws-controltower-examples/aws-control-tower-inspector-enabler'>
  <img title="Share on Twitter" src="https://user-images.githubusercontent.com/50652676/62817740-4c69db00-bb59-11e9-8a79-3580fbbf6d5c.png" />
</a>

</p>
<hr>


We eat, drink, sleep and most importantly love **DevOps**. We are working towards strategies for standardizing architecture while ensuring security for the infrastructure. We are strong believer of the philosophy <b>Bigger problems are always solved by breaking them into smaller manageable problems</b>. Resonating with microservices architecture, it is considered best-practice to run database, cluster, storage in smaller <b>connected yet manageable pieces</b> within the infrastructure.

The AWS Control Tower inspector is an AWS CloudFormation template designed to simplify the process of enabling and configuring AWS inspector in the security account of an AWS Control Tower environment. This template creates essential AWS resources, such as IAM roles, Lambda functions, and SNS topics, to automate the inspector setup based on your specified parameters.

## Prerequisites

Before you proceed, ensure that you have the following prerequisites in place:

1. **AWS Control Tower Environment**: You must have an AWS Control Tower environment set up.

2. **AWS Access**: You should have AWS CLI or AWS Management Console access with sufficient permissions to deploy CloudFormation templates.

3. **Security Account**: Know the AWS account ID of your Security Account.

## Parameters

| Name | Description | Type | Default |
|------|-------------|------| ------- |
| InspectorAuditAccountId | The AWS account ID of the Security(Audit) Account. | String | `n/a` |
| OrganizationId | AWS Organizations ID for the Control Tower. | String | n/a |
| S3SourceBucket | The S3 bucket containing the inspector Lambda deployment package. | String | `""` |
| S3Key| The S3 object key for the inspector Lambda deployment package. | String | `inspector.zip` |
| CfnS3Key| The S3 Path Cfnresponse zip file | String | `cfnresponse.zip` |
| RoleToAssume | The IAM role to be assumed in child accounts to enable inspector. | String | `AWSControlTowerExecution` |
| ExcludedAccounts | Excluded Accounts list. This list should contain Management account, Log Archive and Audit accounts at the minimum | String | `""` |

## Deployment

Follow these steps to deploy the AWS Control Tower inspector template:

1. Sign in to the AWS Management Console or use the AWS CLI.

2. Navigate to the AWS CloudFormation service.

3. Create a new CloudFormation stack.

4. Upload this template or provide the S3 URL where it is located.

5. Fill in the required parameters as described above.

6. Review and confirm the stack creation.

## Functionality

The CloudFormation template creates the following AWS resources:

- **IAM Role:** An IAM role for the inspector Lambda function with necessary permissions.

- **Lambda Function:** The inspector Lambda function, responsible for configuring inspector.

- **CloudWatch Event Rules:** Scheduled rules to trigger the Lambda function periodically and when AWS accounts are created or managed via AWS

## Feedback 
If you come accross a bug or have any feedback, please log it in our [issue tracker](https://github.com/aws-controltower-examples/aws-control-tower-inspector-enabler/issues), or feel free to drop us an email at [hello@clouddrove.com](mailto:hello@clouddrove.com).

If you have found it worth your time, go ahead and give us a ★ on [our GitHub](https://github.com/clouddrove/terraform-aws-vpc-peering)!

## About us

At [CloudDrove][website], we offer expert guidance, implementation support and services to help organisations accelerate their journey to the cloud. Our services include docker and container orchestration, cloud migration and adoption, infrastructure automation, application modernisation and remediation, and performance engineering.

<p align="center">We are <b> The Cloud Experts!</b></p>
<hr />
<p align="center">We ❤️  <a href="https://github.com/clouddrove">Open Source</a> and you can check out <a href="https://github.com/clouddrove">our other modules</a> to get help with your new Cloud ideas.</p>

  [website]: https://clouddrove.com
  [github]: https://github.com/clouddrove
  [linkedin]: https://cpco.io/linkedin
  [twitter]: https://twitter.com/clouddrove/
  [email]: https://clouddrove.com/contact-us.html
  [terraform_modules]: https://github.com/clouddrove?utf8=%E2%9C%93&q=terraform-&type=&language=
