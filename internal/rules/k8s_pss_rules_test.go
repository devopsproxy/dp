package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// pssCluster returns a minimal KubernetesClusterData with a single pod for PSS tests.
func pssCluster(pod models.KubernetesPodData) *models.KubernetesClusterData {
	return &models.KubernetesClusterData{
		ContextName: "test-cluster",
		Pods:        []models.KubernetesPodData{pod},
	}
}

// simplePod returns a KubernetesPodData with one container using the provided
// ContainerData and default pod-level PSS fields (host namespaces all false).
func simplePod(name, ns string, container models.KubernetesContainerData) models.KubernetesPodData {
	return models.KubernetesPodData{
		Name:       name,
		Namespace:  ns,
		Containers: []models.KubernetesContainerData{container},
	}
}

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool { return &b }

// int64Ptr returns a pointer to the given int64 value.
func int64Ptr(i int64) *int64 { return &i }

// ── K8S_POD_PRIVILEGED_CONTAINER ─────────────────────────────────────────────

func TestPSSPrivilegedContainer_Fires_WhenPrivileged(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("my-pod", "default", models.KubernetesContainerData{
			Name:       "app",
			Privileged: true,
		})),
	}
	findings := K8SPSSPrivilegedContainerRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_POD_PRIVILEGED_CONTAINER" {
		t.Errorf("RuleID = %q; want K8S_POD_PRIVILEGED_CONTAINER", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("Severity = %q; want CRITICAL", findings[0].Severity)
	}
}

func TestPSSPrivilegedContainer_Silent_WhenNotPrivileged(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("safe-pod", "default", models.KubernetesContainerData{
			Name:       "app",
			Privileged: false,
		})),
	}
	if got := (K8SPSSPrivilegedContainerRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings; got %d", len(got))
	}
}

func TestPSSPrivilegedContainer_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SPSSPrivilegedContainerRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestPSSPrivilegedContainer_MultipleContainers_OnlyPrivilegedFires(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:      "mixed-pod",
		Namespace: "default",
		Containers: []models.KubernetesContainerData{
			{Name: "safe", Privileged: false},
			{Name: "priv", Privileged: true},
			{Name: "also-safe", Privileged: false},
		},
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	findings := K8SPSSPrivilegedContainerRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].Metadata["container_name"] != "priv" {
		t.Errorf("container_name = %q; want priv", findings[0].Metadata["container_name"])
	}
}

func TestPSSPrivilegedContainer_ResourceID_IsPoName(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("target-pod", "kube-system", models.KubernetesContainerData{
			Name:       "root",
			Privileged: true,
		})),
	}
	findings := K8SPSSPrivilegedContainerRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "target-pod" {
		t.Errorf("ResourceID = %q; want target-pod", findings[0].ResourceID)
	}
}

// ── K8S_POD_HOST_NETWORK ─────────────────────────────────────────────────────

func TestPSSHostNetwork_Fires_WhenHostNetworkTrue(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:        "net-pod",
		Namespace:   "infra",
		HostNetwork: true,
		Containers:  []models.KubernetesContainerData{{Name: "app"}},
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	findings := K8SPSSHostNetworkRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_POD_HOST_NETWORK" {
		t.Errorf("RuleID = %q; want K8S_POD_HOST_NETWORK", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
}

func TestPSSHostNetwork_Silent_WhenHostNetworkFalse(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:        "safe-pod",
		Namespace:   "default",
		HostNetwork: false,
		Containers:  []models.KubernetesContainerData{{Name: "app"}},
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	if got := (K8SPSSHostNetworkRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings; got %d", len(got))
	}
}

func TestPSSHostNetwork_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SPSSHostNetworkRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestPSSHostNetwork_MultiplePods_OnlyHostNetworkFires(t *testing.T) {
	cluster := &models.KubernetesClusterData{
		ContextName: "test-cluster",
		Pods: []models.KubernetesPodData{
			{Name: "safe-a", Namespace: "default", HostNetwork: false},
			{Name: "bad-pod", Namespace: "infra", HostNetwork: true},
			{Name: "safe-b", Namespace: "default", HostNetwork: false},
		},
	}
	findings := K8SPSSHostNetworkRule{}.Evaluate(RuleContext{ClusterData: cluster})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "bad-pod" {
		t.Errorf("ResourceID = %q; want bad-pod", findings[0].ResourceID)
	}
}

func TestPSSHostNetwork_ResourceID_IsPodName(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:        "my-daemonset-pod",
		Namespace:   "kube-system",
		HostNetwork: true,
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	findings := K8SPSSHostNetworkRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "my-daemonset-pod" {
		t.Errorf("ResourceID = %q; want my-daemonset-pod", findings[0].ResourceID)
	}
}

// ── K8S_POD_HOST_PID_OR_IPC ──────────────────────────────────────────────────

func TestPSSHostPIDOrIPC_Fires_WhenHostPIDTrue(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:      "pid-pod",
		Namespace: "default",
		HostPID:   true,
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	findings := K8SPSSHostPIDOrIPCRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_POD_HOST_PID_OR_IPC" {
		t.Errorf("RuleID = %q; want K8S_POD_HOST_PID_OR_IPC", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
}

func TestPSSHostPIDOrIPC_Fires_WhenHostIPCTrue(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:      "ipc-pod",
		Namespace: "default",
		HostIPC:   true,
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	findings := K8SPSSHostPIDOrIPCRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_POD_HOST_PID_OR_IPC" {
		t.Errorf("RuleID = %q; want K8S_POD_HOST_PID_OR_IPC", findings[0].RuleID)
	}
}

func TestPSSHostPIDOrIPC_Silent_WhenBothFalse(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:      "safe-pod",
		Namespace: "default",
		HostPID:   false,
		HostIPC:   false,
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	if got := (K8SPSSHostPIDOrIPCRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings; got %d", len(got))
	}
}

func TestPSSHostPIDOrIPC_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SPSSHostPIDOrIPCRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestPSSHostPIDOrIPC_BothTrue_OneFinding(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:      "both-pod",
		Namespace: "default",
		HostPID:   true,
		HostIPC:   true,
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	findings := K8SPSSHostPIDOrIPCRule{}.Evaluate(ctx)
	// One pod → one finding even when both flags are set.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].Metadata["host_pid"] != true {
		t.Errorf("host_pid metadata = %v; want true", findings[0].Metadata["host_pid"])
	}
	if findings[0].Metadata["host_ipc"] != true {
		t.Errorf("host_ipc metadata = %v; want true", findings[0].Metadata["host_ipc"])
	}
}

// ── K8S_POD_RUN_AS_ROOT ──────────────────────────────────────────────────────

func TestPSSRunAsRoot_Fires_WhenRunAsNonRootNil(t *testing.T) {
	// RunAsNonRoot nil → not enforced → fires
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("root-pod", "default", models.KubernetesContainerData{
			Name:         "app",
			RunAsNonRoot: nil,
		})),
	}
	findings := K8SPSSRunAsRootRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_POD_RUN_AS_ROOT" {
		t.Errorf("RuleID = %q; want K8S_POD_RUN_AS_ROOT", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
}

func TestPSSRunAsRoot_Fires_WhenRunAsUserZero(t *testing.T) {
	// runAsNonRoot == true but runAsUser == 0 → explicit root UID → fires
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("uid0-pod", "default", models.KubernetesContainerData{
			Name:         "app",
			RunAsNonRoot: boolPtr(true),
			RunAsUser:    int64Ptr(0),
		})),
	}
	findings := K8SPSSRunAsRootRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
}

func TestPSSRunAsRoot_Silent_WhenNonRootEnforced(t *testing.T) {
	// runAsNonRoot == true and no root UID → safe
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("safe-pod", "default", models.KubernetesContainerData{
			Name:         "app",
			RunAsNonRoot: boolPtr(true),
			RunAsUser:    int64Ptr(1000),
		})),
	}
	if got := (K8SPSSRunAsRootRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings; got %d", len(got))
	}
}

func TestPSSRunAsRoot_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SPSSRunAsRootRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestPSSRunAsRoot_MultipleContainers_OnlyVulnerableFires(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:      "multi-pod",
		Namespace: "default",
		Containers: []models.KubernetesContainerData{
			{Name: "safe", RunAsNonRoot: boolPtr(true), RunAsUser: int64Ptr(1001)},
			{Name: "risky", RunAsNonRoot: nil}, // not enforced
		},
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	findings := K8SPSSRunAsRootRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].Metadata["container_name"] != "risky" {
		t.Errorf("container_name = %q; want risky", findings[0].Metadata["container_name"])
	}
}

// ── K8S_POD_CAP_SYS_ADMIN ────────────────────────────────────────────────────

func TestPSSCapSysAdmin_Fires_WhenSysAdminAdded(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("cap-pod", "default", models.KubernetesContainerData{
			Name:              "app",
			AddedCapabilities: []string{"SYS_ADMIN"},
		})),
	}
	findings := K8SPSSCapSysAdminRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_POD_CAP_SYS_ADMIN" {
		t.Errorf("RuleID = %q; want K8S_POD_CAP_SYS_ADMIN", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
}

func TestPSSCapSysAdmin_Silent_WhenNoCapabilities(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("safe-pod", "default", models.KubernetesContainerData{
			Name:              "app",
			AddedCapabilities: nil,
		})),
	}
	if got := (K8SPSSCapSysAdminRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings; got %d", len(got))
	}
}

func TestPSSCapSysAdmin_Silent_WhenSysAdminNotInList(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("cap-pod", "default", models.KubernetesContainerData{
			Name:              "app",
			AddedCapabilities: []string{"NET_BIND_SERVICE", "CHOWN"},
		})),
	}
	if got := (K8SPSSCapSysAdminRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings for non-SYS_ADMIN caps; got %d", len(got))
	}
}

func TestPSSCapSysAdmin_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SPSSCapSysAdminRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestPSSCapSysAdmin_MultipleContainers_OnlySysAdminFires(t *testing.T) {
	pod := models.KubernetesPodData{
		Name:      "mixed-cap-pod",
		Namespace: "default",
		Containers: []models.KubernetesContainerData{
			{Name: "safe", AddedCapabilities: []string{"NET_BIND_SERVICE"}},
			{Name: "evil", AddedCapabilities: []string{"SYS_ADMIN", "NET_ADMIN"}},
		},
	}
	ctx := RuleContext{ClusterData: pssCluster(pod)}
	findings := K8SPSSCapSysAdminRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].Metadata["container_name"] != "evil" {
		t.Errorf("container_name = %q; want evil", findings[0].Metadata["container_name"])
	}
}

// ── K8S_POD_NO_SECCOMP ───────────────────────────────────────────────────────

func TestPSSNoSeccomp_Fires_WhenProfileTypeEmpty(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("no-seccomp-pod", "default", models.KubernetesContainerData{
			Name:               "app",
			SeccompProfileType: "",
		})),
	}
	findings := K8SPSSNoSeccompRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_POD_NO_SECCOMP" {
		t.Errorf("RuleID = %q; want K8S_POD_NO_SECCOMP", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
	}
}

func TestPSSNoSeccomp_Fires_WhenUnconfined(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("unconfined-pod", "default", models.KubernetesContainerData{
			Name:               "app",
			SeccompProfileType: "Unconfined",
		})),
	}
	findings := K8SPSSNoSeccompRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].Metadata["seccomp_profile_type"] != "Unconfined" {
		t.Errorf("seccomp_profile_type = %q; want Unconfined", findings[0].Metadata["seccomp_profile_type"])
	}
}

func TestPSSNoSeccomp_Silent_WhenRuntimeDefault(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("secure-pod", "default", models.KubernetesContainerData{
			Name:               "app",
			SeccompProfileType: "RuntimeDefault",
		})),
	}
	if got := (K8SPSSNoSeccompRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings for RuntimeDefault; got %d", len(got))
	}
}

func TestPSSNoSeccomp_Silent_WhenLocalhost(t *testing.T) {
	ctx := RuleContext{
		ClusterData: pssCluster(simplePod("localhost-pod", "default", models.KubernetesContainerData{
			Name:               "app",
			SeccompProfileType: "Localhost",
		})),
	}
	if got := (K8SPSSNoSeccompRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings for Localhost seccomp profile; got %d", len(got))
	}
}

func TestPSSNoSeccomp_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SPSSNoSeccompRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}
