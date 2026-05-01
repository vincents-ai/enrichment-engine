package cspm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vincents-ai/enrichment-engine/pkg/grc"
	"github.com/vincents-ai/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "CSPM_V1"
	CatalogURL  = ""
)

type Provider struct {
	store  storage.Backend
	logger *slog.Logger
}

func New(store storage.Backend, logger *slog.Logger) *Provider {
	return &Provider{store: store, logger: logger}
}

func (p *Provider) Name() string {
	return "cspm"
}

func (p *Provider) Run(ctx context.Context) (int, error) {
	return p.writeEmbeddedControls(ctx)
}

func (p *Provider) writeEmbeddedControls(ctx context.Context) (int, error) {
	controls := embeddedControls()
	count := 0
	for _, ctrl := range controls {
		id := fmt.Sprintf("%s/%s", FrameworkID, ctrl.ControlID)
		if err := p.store.WriteControl(ctx, id, ctrl); err != nil {
			p.logger.Warn("failed to write control", "id", id, "error", err)
			continue
		}
		count++
	}
	if p.logger != nil {
		p.logger.Info("wrote CSPM controls", "count", count)
	}
	return count, nil
}

func embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-1.1",
			Title: "Root Account MFA Enabled", Family: "Identity & Access",
			Description:            "Ensure that multi-factor authentication (MFA) is enabled for the root AWS account. Root account without MFA is a critical security gap that can lead to full account compromise.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-287", "CWE-522"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html", Section: "1.1"}},
			ImplementationGuidance: "Enable MFA on the root account via AWS IAM console. Use hardware MFA device for highest assurance.",
			AssessmentMethods:      []string{"AWS Config Rule: root-account-mfa-enabled", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-1.2",
			Title: "No Access Keys for Root Account", Family: "Identity & Access",
			Description:            "Ensure that no active access keys exist for the root AWS account. Root access keys should never be used for daily operations.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-798", "CWE-326"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html", Section: "1.2"}},
			ImplementationGuidance: "Delete any existing root access keys. Use IAM roles and federated access instead.",
			AssessmentMethods:      []string{"AWS Config Rule: root-access-keys-check", "IAM Credential Report"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-1.3",
			Title: "IAM Password Policy Enforces Complexity", Family: "Identity & Access",
			Description:            "Ensure that the IAM password policy enforces minimum password length of 14 characters, requires uppercase, lowercase, numbers, and symbols, and prevents password reuse.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-521", "CWE-265"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html", Section: "1.3"}},
			ImplementationGuidance: "Configure password policy via AWS IAM console or CLI: minimum length 14, require symbols, numbers, uppercase, lowercase, prevent reuse of last 24 passwords.",
			AssessmentMethods:      []string{"AWS Config Rule: iam-password-policy", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-1.4",
			Title: "Unused IAM Credentials Rotated", Family: "Identity & Access",
			Description:            "Ensure that IAM credentials that have not been used in 45 or more days are disabled or rotated. Unused credentials increase the attack surface.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-798"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding_unused.html", Section: "1.4"}},
			ImplementationGuidance: "Generate IAM credential report, identify unused access keys and passwords older than 45 days, disable or rotate them.",
			AssessmentMethods:      []string{"AWS Config Rule: unused-credentials", "IAM Credential Report"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-1.5",
			Title: "Cross-Account Role Trust Policies Restricted", Family: "Identity & Access",
			Description:            "Ensure that IAM roles with cross-account trust policies restrict access to trusted accounts only and avoid wildcard principals.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-862"},
			References:             []grc.Reference{{Source: "AWS IAM Best Practices", URL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html", Section: "Trust Policies"}},
			ImplementationGuidance: "Audit all IAM role trust policies. Remove any that grant access to '*' or untrusted account ARNs.",
			AssessmentMethods:      []string{"AWS IAM Access Analyzer", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-2.1",
			Title: "Security Groups Restrict Unrestricted Ports", Family: "Network Security",
			Description:            "Ensure that no security group allows unrestricted ingress (0.0.0.0/0) to common sensitive ports such as 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL), and 1433 (MSSQL).",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-668"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-groups.html", Section: "4.1"}},
			ImplementationGuidance: "Remove or restrict inbound rules allowing 0.0.0.0/0 on sensitive ports. Use VPN or bastion hosts for administrative access.",
			AssessmentMethods:      []string{"AWS Config Rule: restricted-ssh", "AWS Security Hub"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-2.2",
			Title: "No Public-Facing Resources Without Approval", Family: "Network Security",
			Description:            "Ensure that EC2 instances, RDS databases, EFS file systems, and load balancers are not publicly accessible without explicit security approval and documentation.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-668"},
			References:             []grc.Reference{{Source: "AWS Well-Architected Framework", URL: "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/", Section: "Security Pillar"}},
			ImplementationGuidance: "Tag all public-facing resources with an approved tag. Implement SCPs to prevent creation of public resources without tags.",
			AssessmentMethods:      []string{"AWS Config Rule", "AWS Resource Tagging", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-2.3",
			Title: "VPC Flow Logs Enabled", Family: "Network Security",
			Description:            "Ensure that VPC Flow Logs are enabled for all VPCs to capture network traffic metadata for security monitoring, troubleshooting, and compliance.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-778"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html", Section: "3.9"}},
			ImplementationGuidance: "Enable VPC Flow Logs for all VPCs, sending logs to CloudWatch Logs or S3 with appropriate retention policies.",
			AssessmentMethods:      []string{"AWS Config Rule: vpc-flow-logs-enabled", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-2.4",
			Title: "Network ACLs Configured for Least Privilege", Family: "Network Security",
			Description:            "Ensure that network ACLs are configured to deny traffic by default and only allow necessary inbound and outbound traffic.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-284", "CWE-668"},
			References:             []grc.Reference{{Source: "AWS VPC Documentation", URL: "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html", Section: "Network ACLs"}},
			ImplementationGuidance: "Review and restrict default network ACLs. Ensure deny-all-default rule is in place.",
			AssessmentMethods:      []string{"AWS Config Rule", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-2.5",
			Title: "All Security Groups Attached to Resources", Family: "Network Security",
			Description:            "Ensure that every security group is attached to at least one resource. Orphaned security groups may indicate misconfigurations or unused attack surface.",
			Level:                  "low",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "AWS Security Best Practices", URL: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-best-practices.html", Section: "SG Management"}},
			ImplementationGuidance: "Audit all security groups and identify those not attached to any ENI. Delete orphaned security groups.",
			AssessmentMethods:      []string{"AWS Config Rule", "Custom Lambda", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-3.1",
			Title: "S3 Buckets Have No Public Access", Family: "Data Protection",
			Description:            "Ensure that S3 buckets do not allow public access. Block public access at the bucket level and account level.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-306", "CWE-200"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", Section: "2.1"}},
			ImplementationGuidance: "Enable 'Block all public access' on all S3 buckets. Review bucket policies for any 'Principal: *' grants.",
			AssessmentMethods:      []string{"AWS Config Rule: s3-bucket-public-read-prohibited", "S3 Access Analyzer"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-3.2",
			Title: "Encryption at Rest Using KMS", Family: "Data Protection",
			Description:            "Ensure that all data stores (S3, EBS, RDS, EFS, DynamoDB) use encryption at rest with AWS KMS managed keys or customer-managed CMKs.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-311", "CWE-326"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/kms/latest/developerguide/", Section: "3.8"}},
			ImplementationGuidance: "Enable default encryption on S3 buckets. Enable EBS encryption by default at the account level. Use KMS CMKs for RDS and other services.",
			AssessmentMethods:      []string{"AWS Config Rule: encrypted-volumes", "AWS Config Rule: s3-bucket-server-side-encryption-enabled"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-3.3",
			Title: "Encryption in Transit (TLS) Enforced", Family: "Data Protection",
			Description:            "Ensure that all data in transit is encrypted using TLS 1.2 or higher. This includes API endpoints, load balancers, RDS connections, and internal service communication.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-319", "CWE-326"},
			References:             []grc.Reference{{Source: "AWS Security Best Practices", URL: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html", Section: "TLS Configuration"}},
			ImplementationGuidance: "Configure ALB/NLB listeners with TLS 1.2 minimum. Enable RDS SSL enforcement. Use ACM for certificate management.",
			AssessmentMethods:      []string{"AWS Config Rule", "SSL Labs Scan", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-3.4",
			Title: "No Public EBS Snapshots", Family: "Data Protection",
			Description:            "Ensure that no EBS snapshots are shared publicly. Public snapshots can expose sensitive data to unauthorized parties.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-200", "CWE-306"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html", Section: "3.6"}},
			ImplementationGuidance: "Audit all EBS snapshots for public sharing. Remove any public share permissions immediately.",
			AssessmentMethods:      []string{"AWS Trusted Advisor", "AWS Config Rule", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-3.5",
			Title: "RDS Instances Not Publicly Accessible", Family: "Data Protection",
			Description:            "Ensure that RDS database instances are not publicly accessible. RDS instances should only be accessible from within the VPC.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-306", "CWE-668"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html", Section: "3.7"}},
			ImplementationGuidance: "Set PubliclyAccessible=false on all RDS instances. Ensure database subnets are private.",
			AssessmentMethods:      []string{"AWS Config Rule: rds-instance-public-access-check", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-4.1",
			Title: "CloudTrail Enabled in All Regions", Family: "Logging & Monitoring",
			Description:            "Ensure that AWS CloudTrail is enabled in all regions to log all API calls for audit, compliance, and security investigation purposes.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-778"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/", Section: "2.1"}},
			ImplementationGuidance: "Enable CloudTrail in all regions with log file validation, encryption using KMS CMK, and S3 bucket with appropriate lifecycle policies.",
			AssessmentMethods:      []string{"AWS Config Rule: cloud-trail-enabled", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-4.2",
			Title: "CloudWatch Alarms Configured", Family: "Logging & Monitoring",
			Description:            "Ensure that CloudWatch alarms are configured for critical security events including unauthorized API calls, suspicious login attempts, and resource policy changes.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-778"},
			References:             []grc.Reference{{Source: "AWS Monitoring Best Practices", URL: "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/", Section: "Alarms"}},
			ImplementationGuidance: "Create CloudWatch alarms for: Console sign-in without MFA, IAM policy changes, security group changes, CloudTrail log delivery failures.",
			AssessmentMethods:      []string{"AWS Config Rule", "CloudWatch Console", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-4.3",
			Title: "AWS Config Rules Enabled", Family: "Logging & Monitoring",
			Description:            "Ensure that AWS Config is enabled in all regions to track resource configuration changes and enable compliance auditing.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-778"},
			References:             []grc.Reference{{Source: "CIS AWS Benchmark", URL: "https://docs.aws.amazon.com/config/latest/developerguide/", Section: "2.2"}},
			ImplementationGuidance: "Enable AWS Config recorder in all regions. Enable required managed rules for CIS benchmark compliance. Send notifications to SNS.",
			AssessmentMethods:      []string{"AWS Config Console", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-4.4",
			Title: "GuardDuty Enabled", Family: "Logging & Monitoring",
			Description:            "Ensure that Amazon GuardDuty is enabled to provide intelligent threat detection for unauthorized behavior and malicious activity.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-693"},
			References:             []grc.Reference{{Source: "AWS GuardDuty Documentation", URL: "https://docs.aws.amazon.com/guardduty/latest/ug/", Section: "Enablement"}},
			ImplementationGuidance: "Enable GuardDuty in all regions. Configure S3 protection, EKS protection, and Lambda protection. Set up findings export to S3 or SNS.",
			AssessmentMethods:      []string{"AWS GuardDuty Console", "AWS CLI"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AZURE-2.1",
			Title: "Azure Network Security Groups Restrict Access", Family: "Network Security",
			Description:            "Ensure that Azure Network Security Groups (NSGs) do not allow unrestricted inbound access to sensitive ports from the internet.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-668"},
			References:             []grc.Reference{{Source: "CIS Microsoft Azure Benchmark", URL: "https://docs.microsoft.com/azure/virtual-network/network-security-groups-overview", Section: "5.1"}},
			ImplementationGuidance: "Review all NSG rules. Deny inbound access on ports 22, 3389, 1433, 3306 from Internet. Use Azure Bastion for administrative access.",
			AssessmentMethods:      []string{"Azure Security Center", "Azure Policy", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AZURE-3.1",
			Title: "Azure Storage Account Encryption Enabled", Family: "Data Protection",
			Description:            "Ensure that Azure Storage accounts have encryption at rest enabled using Microsoft-managed or customer-managed keys.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-311", "CWE-326"},
			References:             []grc.Reference{{Source: "CIS Microsoft Azure Benchmark", URL: "https://docs.microsoft.com/azure/storage/common/storage-service-encryption", Section: "3.4"}},
			ImplementationGuidance: "Enable storage account encryption with customer-managed keys stored in Azure Key Vault. Ensure secure transfer required is enabled.",
			AssessmentMethods:      []string{"Azure Policy", "Azure Security Center"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AZURE-4.1",
			Title: "Azure Monitor Diagnostic Settings Configured", Family: "Logging & Monitoring",
			Description:            "Ensure that Azure Monitor diagnostic settings are configured for all critical resources to send logs and metrics to a Log Analytics workspace.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-778"},
			References:             []grc.Reference{{Source: "CIS Microsoft Azure Benchmark", URL: "https://docs.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings", Section: "4.1"}},
			ImplementationGuidance: "Create diagnostic settings on all critical resources to send Activity Log, metrics, and resource logs to a centralized Log Analytics workspace.",
			AssessmentMethods:      []string{"Azure Policy", "Azure Monitor", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-GCP-2.1",
			Title: "GCP Firewall Rules Restrict Public Access", Family: "Network Security",
			Description:            "Ensure that GCP VPC firewall rules do not allow unrestricted ingress (0.0.0.0/0) to common sensitive ports.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-668"},
			References:             []grc.Reference{{Source: "CIS GCP Benchmark", URL: "https://cloud.google.com/vpc/docs/firewalls", Section: "4.1"}},
			ImplementationGuidance: "Review all VPC firewall rules. Remove or restrict rules allowing 0.0.0.0/0 on ports 22, 3389, 3306, 5432. Use Identity-Aware Proxy for SSH.",
			AssessmentMethods:      []string{"gcloud compute firewall-rules list", "Security Command Center"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-GCP-3.1",
			Title: "GCP Storage Bucket Encryption Enabled", Family: "Data Protection",
			Description:            "Ensure that GCP Cloud Storage buckets use encryption with Google-managed or customer-managed encryption keys (CMEK).",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-311", "CWE-326"},
			References:             []grc.Reference{{Source: "CIS GCP Benchmark", URL: "https://cloud.google.com/storage/docs/encryption", Section: "5.1"}},
			ImplementationGuidance: "Enable default encryption with CMEK for all new buckets. Migrate existing buckets to CMEK. Restrict public access.",
			AssessmentMethods:      []string{"gcloud storage buckets describe", "Security Command Center"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-5.1",
			Title: "AMI Sharing Restricted", Family: "Compute Security",
			Description:            "Ensure that AMIs are not shared with unauthorized AWS accounts. Shared AMIs can contain sensitive configurations or vulnerabilities.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-200", "CWE-284"},
			References:             []grc.Reference{{Source: "AWS Security Best Practices", URL: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html", Section: "AMI Sharing"}},
			ImplementationGuidance: "Audit all AMI sharing permissions. Remove shares with unauthorized accounts. Use RAM for controlled sharing.",
			AssessmentMethods:      []string{"AWS Config Rule", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-5.2",
			Title: "EC2 Instances Use IAM Roles", Family: "Compute Security",
			Description:            "Ensure that EC2 instances use IAM roles for AWS service authentication instead of embedded access keys.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-798", "CWE-326"},
			References:             []grc.Reference{{Source: "AWS IAM Best Practices", URL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html", Section: "IAM Roles"}},
			ImplementationGuidance: "Attach IAM instance profiles to all EC2 instances. Remove any hardcoded AWS credentials from instance metadata or application code.",
			AssessmentMethods:      []string{"AWS Config Rule", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-5.3",
			Title: "Container Privileged Mode Disabled", Family: "Compute Security",
			Description:            "Ensure that ECS containers and EKS pods do not run in privileged mode. Privileged containers have full access to the host system.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-250", "CWE-269"},
			References:             []grc.Reference{{Source: "CIS Docker/Kubernetes Benchmark", URL: "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html", Section: "Privileged Mode"}},
			ImplementationGuidance: "Set privileged=false in ECS task definitions. Use Pod Security Standards in EKS to restrict privileged pods.",
			AssessmentMethods:      []string{"ECS Task Definition Review", "EKS Admission Controller", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-6.1",
			Title: "CIS Benchmark Alignment", Family: "Compliance",
			Description:            "Ensure that cloud resources comply with CIS Benchmarks for the respective cloud provider (AWS, Azure, GCP) at the Level 1 or Level 2 profile.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "CIS Benchmarks", URL: "https://www.cisecurity.org/cis-benchmarks/", Section: "Cloud Benchmarks"}},
			ImplementationGuidance: "Enable AWS Config rules, Azure Policy, and GCP Organization Policies aligned to CIS benchmarks. Automate compliance scanning.",
			AssessmentMethods:      []string{"AWS Security Hub CIS Standard", "Azure Security Center CIS Benchmark", "GCP Security Command Center"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-6.2",
			Title: "Resource Tagging Enforced", Family: "Compliance",
			Description:            "Ensure that all cloud resources have mandatory tags for ownership, environment, cost center, and compliance classification.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "AWS Tagging Best Practices", URL: "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html", Section: "Tagging"}},
			ImplementationGuidance: "Implement tag policies via AWS Organizations SCPs, Azure Policy, or GCP Organization Policies. Automate enforcement.",
			AssessmentMethods:      []string{"AWS Config Rule: required-tags", "Azure Policy", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "CSPM-AWS-6.3",
			Title: "Cost Anomaly Detection Enabled", Family: "Compliance",
			Description:            "Ensure that AWS Cost Anomaly Detection is enabled to detect unexpected spending that may indicate compromised resources or crypto-mining.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-385", "CWE-770"},
			References:             []grc.Reference{{Source: "AWS Cost Management", URL: "https://docs.aws.amazon.com/cost-management/latest/userguide/anomaly-detection.html", Section: "Cost Anomaly"}},
			ImplementationGuidance: "Enable AWS Cost Anomaly Detection with a monitoring threshold. Configure alert subscriptions to SNS or email.",
			AssessmentMethods:      []string{"AWS Cost Explorer", "AWS Budgets", "Manual Review"},
		},
	}
}
