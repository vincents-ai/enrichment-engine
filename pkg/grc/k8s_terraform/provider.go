package k8s_terraform

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/shift/enrichment-engine/pkg/grc"
	"github.com/shift/enrichment-engine/pkg/storage"
)

const (
	FrameworkID = "K8S_TF_V1"
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
	return "k8s_terraform"
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
		p.logger.Info("wrote K8S/Terraform controls", "count", count)
	}
	return count, nil
}

func embeddedControls() []grc.Control {
	return []grc.Control{
		{
			Framework: FrameworkID, ControlID: "K8S-1.1",
			Title: "API Server Audit Logging Enabled", Family: "Kubernetes",
			Description:            "Ensure that the Kubernetes API server is configured with audit logging enabled, capturing all requests to the API server for security monitoring and incident investigation.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-778", "CWE-775"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://www.cisecurity.org/benchmark/kubernetes", Section: "1.2.1"}},
			ImplementationGuidance: "Configure --audit-log-path and --audit-policy-file on the API server. Define an audit policy that logs Metadata level for all requests and RequestResponse for write operations.",
			AssessmentMethods:      []string{"kube-bench check 1.2.1", "API server process arguments", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.2",
			Title: "etcd Encryption at Rest", Family: "Kubernetes",
			Description:            "Ensure that etcd data is encrypted at rest using a supported encryption provider configuration. Unencrypted etcd stores secrets in plaintext.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-311", "CWE-326"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/", Section: "1.2.33"}},
			ImplementationGuidance: "Create an EncryptionConfiguration resource with providers array. Set --encryption-provider-config on the API server. Encrypt existing secrets with 'kubectl get secrets --all-namespaces -o json | kubectl replace -f -'.",
			AssessmentMethods:      []string{"kube-bench check 1.2.33", "API server process arguments", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.3",
			Title: "RBAC Policies Enforced", Family: "Kubernetes",
			Description:            "Ensure that RBAC authorization is enabled and Role-Based Access Control policies follow the principle of least privilege. No ClusterRoleBindings should grant wildcard permissions.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-862", "CWE-269"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/reference/access-authn-authz/rbac/", Section: "1.2.7"}},
			ImplementationGuidance: "Enable --authorization-mode=RBAC. Audit all ClusterRoleBindings for overly broad permissions. Remove binding to 'cluster-admin' for non-admin users. Use Roles instead of ClusterRoles where possible.",
			AssessmentMethods:      []string{"kube-bench check 1.2.7", "kubectl get clusterrolebindings", "rbac-police scanner"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.4",
			Title: "Network Policies Configured", Family: "Kubernetes",
			Description:            "Ensure that all namespaces have default-deny NetworkPolicies configured. Network policies should explicitly define allowed ingress and egress traffic for each workload.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-284", "CWE-668"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/concepts/services-networking/network-policies/", Section: "5.3.2"}},
			ImplementationGuidance: "Create default-deny ingress and egress NetworkPolicies in every namespace. Add specific allow rules for each workload. Use a network policy controller like Calico or Cilium.",
			AssessmentMethods:      []string{"kubectl get networkpolicies --all-namespaces", "kube-bench check 5.3.2", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.5",
			Title: "Pod Security Standards Enforced", Family: "Kubernetes",
			Description:            "Ensure that Pod Security Standards are enforced via namespace labels or admission controllers, restricting privileged containers, host namespace sharing, and dangerous capabilities.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-250", "CWE-269", "CWE-265"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/", Section: "5.2"}},
			ImplementationGuidance: "Label namespaces with pod-security.kubernetes.io/enforce=restricted or baseline. Use the Pod Security Admission controller or OPA/Gatekeeper to enforce. Migrate from PodSecurityPolicy.",
			AssessmentMethods:      []string{"kubectl get namespaces --show-labels", "kube-bench check 5.2.x", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.6",
			Title: "Secrets Management via External Provider", Family: "Kubernetes",
			Description:            "Ensure that Kubernetes secrets are managed via an external secrets provider (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) rather than native Kubernetes Secret objects.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-311", "CWE-798", "CWE-522"},
			References:             []grc.Reference{{Source: "NIST SP 800-53 SC-28", URL: "https://external-secrets.io/latest/", Section: "External Secrets"}},
			ImplementationGuidance: "Deploy External Secrets Operator or CSI Secrets Store driver. Configure SecretStore and ExternalSecret resources. Rotate secrets automatically via external provider.",
			AssessmentMethods:      []string{"kubectl get external-secrets --all-namespaces", "Audit native secrets usage", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.7",
			Title: "Service Mesh mTLS Enforcement", Family: "Kubernetes",
			Description:            "Ensure that service mesh mutual TLS (mTLS) is enforced for all inter-service communication within the cluster, preventing plaintext traffic between pods.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-319", "CWE-326"},
			References:             []grc.Reference{{Source: "Istio Security Best Practices", URL: "https://istio.io/latest/docs/concepts/security/", Section: "mTLS"}},
			ImplementationGuidance: "Enable STRICT mTLS mode in Istio PeerAuthentication. Configure Linkerd with auto-inject. Verify mTLS using service mesh metrics and dashboard.",
			AssessmentMethods:      []string{"istioctl analyze", "linkerd check", "Service mesh metrics", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.8",
			Title: "Admission Controllers Configured", Family: "Kubernetes",
			Description:            "Ensure that recommended admission controllers are enabled including NamespaceLifecycle, LimitRanger, ServiceAccount, DefaultStorageClass, ResourceQuota, and PodSecurity admission.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-400", "CWE-770", "CWE-250"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/", Section: "1.2.6"}},
			ImplementationGuidance: "Enable recommended admission controllers via --enable-admission-plugins. Add OPA/Gatekeeper or Kyverno for custom policy enforcement.",
			AssessmentMethods:      []string{"kube-bench check 1.2.6", "API server process arguments", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.9",
			Title: "Container Image Provenance Verified", Family: "Kubernetes",
			Description:            "Ensure that all container images are from trusted registries, signed (Sigstore/Cosign or Notary), and verified before deployment via admission controllers.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-829", "CWE-353"},
			References:             []grc.Reference{{Source: "Sigstore Documentation", URL: "https://docs.sigstore.dev/", Section: "Image Signing"}},
			ImplementationGuidance: "Sign images with Cosign. Deploy Kyverno or OPA/Gatekeeper admission policy to verify signatures. Restrict image pull to approved registries.",
			AssessmentMethods:      []string{"Admission controller logs", "Cosign verify", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.10",
			Title: "Resource Quotas and Limits Defined", Family: "Kubernetes",
			Description:            "Ensure that all namespaces have ResourceQuotas configured and all pods have resource requests and limits defined to prevent resource exhaustion and denial of service.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-400", "CWE-770"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/concepts/policy/resource-quotas/", Section: "5.4"}},
			ImplementationGuidance: "Create LimitRange objects for default resource limits in each namespace. Create ResourceQuota objects per namespace. Enforce via admission controllers.",
			AssessmentMethods:      []string{"kubectl get resourcequotas --all-namespaces", "kubectl get limitranges --all-namespaces", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.11",
			Title: "Node Hardening and OS Security", Family: "Kubernetes",
			Description:            "Ensure that Kubernetes worker nodes use a hardened OS (Bottlerocket, Flatcar), have minimal installed packages, and run security updates automatically.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16", "CWE-269"},
			References:             []grc.Reference{{Source: "NIST SP 800-190", URL: "https://csrc.nist.gov/publications/detail/sp/800-190/final", Section: "Node Security"}},
			ImplementationGuidance: "Use Bottlerocket or Flatcar Container Linux for worker nodes. Enable automatic security updates. Disable unnecessary services. Use node pools for isolation.",
			AssessmentMethods:      []string{"Node OS audit", "kube-bench node checks", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.12",
			Title: "API Server Authentication and Authorization", Family: "Kubernetes",
			Description:            "Ensure that the Kubernetes API server uses strong authentication mechanisms (client certificates, OIDC tokens) and that anonymous authentication is disabled.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-287", "CWE-288"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/", Section: "1.2.1-1.2.8"}},
			ImplementationGuidance: "Disable --anonymous-auth. Configure OIDC provider for user authentication. Use client certificate authentication for service accounts. Enable authorization modes RBAC,Node.",
			AssessmentMethods:      []string{"kube-bench check 1.2.x", "API server process arguments", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.13",
			Title: "etcd Access Restriction", Family: "Kubernetes",
			Description:            "Ensure that etcd is only accessible from the API server nodes via TLS mutual authentication, and that etcd endpoints are not exposed to the cluster network.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-319"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/", Section: "1.2.12"}},
			ImplementationGuidance: "Configure etcd with --client-cert-auth and --peer-client-cert-auth. Restrict etcd firewall rules to API server nodes only. Use dedicated etcd certificates.",
			AssessmentMethods:      []string{"kube-bench check 1.2.12", "etcd configuration audit", "Network firewall rules review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.14",
			Title: "Workload Identity and Service Account Token Security", Family: "Kubernetes",
			Description:            "Ensure that pods use projected service account tokens with bounded lifetimes, and that automatic mounting of service account tokens is disabled for pods that do not need API access.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-287", "CWE-639"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/", Section: "5.1.5"}},
			ImplementationGuidance: "Set automountServiceAccountToken: false on pods that do not need API access. Use projected volume tokens with 1-hour expiry. Use workload identity federation for cloud API access.",
			AssessmentMethods:      []string{"Pod spec audit", "kube-bench check 5.1.5", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.15",
			Title: "Kubernetes Dashboard Access Restricted", Family: "Kubernetes",
			Description:            "Ensure that the Kubernetes Dashboard is not deployed in production clusters, or if deployed, access is restricted with strong authentication and RBAC.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-284", "CWE-306"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/", Section: "Dashboard Security"}},
			ImplementationGuidance: "Remove Kubernetes Dashboard from production clusters. If required, enforce OIDC authentication, restrict to specific namespaces, and enable audit logging.",
			AssessmentMethods:      []string{"kubectl get deploy --all-namespaces", "Dashboard RBAC review", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "K8S-1.16",
			Title: "Kubelet Configuration Security", Family: "Kubernetes",
			Description:            "Ensure that kubelet is configured with secure defaults including anonymous auth disabled, read-only port disabled, streaming connection idle timeout, and event recording enabled.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-287", "CWE-16"},
			References:             []grc.Reference{{Source: "CIS Kubernetes Benchmark", URL: "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/", Section: "4.2.x"}},
			ImplementationGuidance: "Set --anonymous-auth=false, --read-only-port=0, --streaming-connection-idle-timeout=5m, --event-qps=0 on kubelet. Enable certificate rotation.",
			AssessmentMethods:      []string{"kube-bench check 4.2.x", "kubelet config audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.1",
			Title: "Terraform State File Encryption", Family: "Terraform/IaC",
			Description:            "Ensure that Terraform state files are encrypted at rest. State files contain sensitive data including secrets, passwords, and private keys in plaintext.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-311", "CWE-326", "CWE-312"},
			References:             []grc.Reference{{Source: "Terraform Best Practices", URL: "https://developer.hashicorp.com/terraform/cloud/guides/recommended-practices", Section: "State Security"}},
			ImplementationGuidance: "Use Terraform Cloud or remote backends (S3+KMS, GCS+CMEK, Azure Blob+CMK) with server-side encryption. Enable state encryption at rest.",
			AssessmentMethods:      []string{"Backend configuration review", "Terraform Cloud settings", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.2",
			Title: "Remote State Backend with Access Controls", Family: "Terraform/IaC",
			Description:            "Ensure that Terraform state is stored in a secure remote backend (S3, GCS, Terraform Cloud, TFE) with appropriate access controls, versioning, and audit logging.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-284", "CWE-639", "CWE-311"},
			References:             []grc.Reference{{Source: "Terraform Documentation", URL: "https://developer.hashicorp.com/terraform/language/settings/backends", Section: "Backends"}},
			ImplementationGuidance: "Configure remote backend with IAM policies restricting access. Enable bucket versioning. Enable access logging. Use state locking.",
			AssessmentMethods:      []string{"Backend configuration review", "IAM policy audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.3",
			Title: "No Secrets in Terraform State", Family: "Terraform/IaC",
			Description:            "Ensure that no secrets, passwords, API keys, or certificates are stored in Terraform state files. All sensitive values should reference external secret managers.",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-312", "CWE-798", "CWE-522"},
			References:             []grc.Reference{{Source: "Terraform Security", URL: "https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables", Section: "Sensitive Data"}},
			ImplementationGuidance: "Mark all sensitive variables as 'sensitive = true'. Use Vault provider, AWS Secrets Manager, or environment variables for secret injection. Run tfsec or checkov to detect secrets.",
			AssessmentMethods:      []string{"tfsec scan", "checkov scan", "State file analysis", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.4",
			Title: "Terraform Module Versioning", Family: "Terraform/IaC",
			Description:            "Ensure that all Terraform modules use pinned versions (semver constraints) to prevent unexpected changes from upstream module updates.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-829", "CWE-353"},
			References:             []grc.Reference{{Source: "Terraform Module Best Practices", URL: "https://developer.hashicorp.com/terraform/language/modules/sources", Section: "Versioning"}},
			ImplementationGuidance: "Pin all module source versions using semantic versioning constraints (e.g., '>= 1.2.0, < 2.0.0'). Use Terraform module registry. Lock module versions in .terraform.lock.hcl.",
			AssessmentMethods:      []string{"Terraform configuration review", ".terraform.lock.hcl audit", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.5",
			Title: "Drift Detection Enabled", Family: "Terraform/IaC",
			Description:            "Ensure that automated drift detection is enabled to identify when actual infrastructure state diverges from the Terraform-defined desired state.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16", "CWE-778"},
			References:             []grc.Reference{{Source: "Terraform Drift Detection", URL: "https://developer.hashicorp.com/terraform/cloud/guides/recommended-practices", Section: "Drift"}},
			ImplementationGuidance: "Schedule regular 'terraform plan' runs via CI/CD. Use Terraform Cloud drift detection. Integrate drift alerts into incident management.",
			AssessmentMethods:      []string{"Terraform Cloud drift detection", "CI/CD pipeline logs", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.6",
			Title: "Plan Review Requirements", Family: "Terraform/IaC",
			Description:            "Ensure that all Terraform plan outputs are reviewed by at least one team member before apply. Automated approval should require human confirmation for production environments.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-16"},
			References:             []grc.Reference{{Source: "Terraform Workflow", URL: "https://developer.hashicorp.com/terraform/cloud/guides/recommended-practices", Section: "Review"}},
			ImplementationGuidance: "Enable Sentinel policies in Terraform Cloud. Configure manual approval for production workspaces. Use PR-based review with plan output comments.",
			AssessmentMethods:      []string{"Terraform Cloud policy checks", "PR review logs", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.7",
			Title: "Variable Validation Rules", Family: "Terraform/IaC",
			Description:            "Ensure that all Terraform input variables have validation rules defined to prevent invalid configurations from being applied to infrastructure.",
			Level:                  "medium",
			RelatedCWEs:            []string{"CWE-20", "CWE-16"},
			References:             []grc.Reference{{Source: "Terraform Variables", URL: "https://developer.hashicorp.com/terraform/language/values/variables", Section: "Validation"}},
			ImplementationGuidance: "Add validation blocks to all variables. Validate CIDR blocks, instance types, naming conventions, and tag formats. Use regex patterns for string validation.",
			AssessmentMethods:      []string{"Terraform configuration review", "terraform validate", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.8",
			Title: "Provider Configuration Security", Family: "Terraform/IaC",
			Description:            "Ensure that Terraform provider configurations do not hardcode credentials and use secure authentication methods (instance profiles, workload identity, Vault dynamic credentials).",
			Level:                  "critical",
			RelatedCWEs:            []string{"CWE-798", "CWE-312", "CWE-259"},
			References:             []grc.Reference{{Source: "Terraform Provider Auth", URL: "https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials", Section: "Provider Auth"}},
			ImplementationGuidance: "Use provider blocks with no hardcoded credentials. Use Vault dynamic secrets provider. Configure AWS instance profiles or GCP workload identity. Use Terraform Cloud dynamic provider credentials.",
			AssessmentMethods:      []string{"tfsec scan", "checkov scan", "Git history scan for secrets", "Manual Review"},
		},
		{
			Framework: FrameworkID, ControlID: "TF-1.9",
			Title: "CI/CD Pipeline Security for Terraform", Family: "Terraform/IaC",
			Description:            "Ensure that CI/CD pipelines executing Terraform have secure configurations: minimal secrets, branch protection, signed commits, and isolated execution environments.",
			Level:                  "high",
			RelatedCWEs:            []string{"CWE-250", "CWE-798", "CWE-494"},
			References:             []grc.Reference{{Source: "SLSA Framework", URL: "https://slsa.dev/", Section: "Pipeline Security"}},
			ImplementationGuidance: "Use OIDC-based authentication in CI/CD (GitHub Actions, GitLab CI). Implement branch protection rules. Sign commits. Run Terraform in ephemeral, isolated runners.",
			AssessmentMethods:      []string{"CI/CD configuration review", "Branch protection audit", "Manual Review"},
		},
	}
}
