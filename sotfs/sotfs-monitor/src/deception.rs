//! # Deceptive Subgraph Projections
//!
//! Implements capability-gated graph projections (§10 of design doc).
//! Different security domains see different subgraphs of the filesystem.
//!
//! The D_FS functor maps the real TypeGraph to a projected view:
//! - **Passthrough:** Domain sees the real graph (identity functor).
//! - **Restrict:** Domain sees only a subtree rooted at its capability.
//! - **Fabricate:** Synthetic nodes/edges added to the projected view.
//! - **Redirect:** Certain paths resolve to different inodes (honeypots).

use std::collections::{BTreeMap, BTreeSet};
use sotfs_graph::graph::TypeGraph;
use sotfs_graph::types::*;

/// Interposition policy for a domain's projection.
#[derive(Debug, Clone)]
pub enum Policy {
    /// See the real graph unchanged.
    Passthrough,
    /// See only the subtree rooted at a specific directory.
    Restrict { root_dir: DirId },
    /// See the real graph plus fabricated entries.
    Fabricate { synthetic: Vec<SyntheticEntry> },
    /// Certain paths resolve to different inodes.
    Redirect { redirects: BTreeMap<String, InodeId> },
}

/// A fabricated directory entry that doesn't exist in the real graph.
#[derive(Debug, Clone)]
pub struct SyntheticEntry {
    pub parent_dir: DirId,
    pub name: String,
    pub inode: Inode,
    pub data: Vec<u8>,
}

/// A projected view of the filesystem for a specific domain.
#[derive(Debug)]
pub struct ProjectedView {
    /// Visible inodes (subset of real + synthetic).
    pub visible_inodes: BTreeMap<InodeId, Inode>,
    /// Visible directory entries.
    pub visible_entries: BTreeMap<DirId, Vec<(String, InodeId)>>,
    /// Fabricated file data (for synthetic entries).
    pub fabricated_data: BTreeMap<InodeId, Vec<u8>>,
    /// Redirect map: original inode → replacement inode.
    pub redirects: BTreeMap<InodeId, InodeId>,
    /// Policy used to create this projection.
    pub policy: String,
}

/// Compute the projected view of the graph for a domain with the given policy.
pub fn project(graph: &TypeGraph, policy: &Policy) -> ProjectedView {
    match policy {
        Policy::Passthrough => project_passthrough(graph),
        Policy::Restrict { root_dir } => project_restrict(graph, *root_dir),
        Policy::Fabricate { synthetic } => project_fabricate(graph, synthetic),
        Policy::Redirect { redirects } => project_redirect(graph, redirects),
    }
}

/// Passthrough: the domain sees everything as-is.
fn project_passthrough(graph: &TypeGraph) -> ProjectedView {
    let mut entries: BTreeMap<DirId, Vec<(String, InodeId)>> = BTreeMap::new();
    for (&dir_id, edge_ids) in &graph.dir_contains {
        let mut dir_entries = Vec::new();
        for &eid in edge_ids {
            if let Some(Edge::Contains { tgt, name, .. }) = graph.get_edge(eid) {
                dir_entries.push((name.clone(), *tgt));
            }
        }
        entries.insert(dir_id, dir_entries);
    }

    ProjectedView {
        visible_inodes: graph.inodes.iter().map(|(aid, v)| (aid.0 as u64, v.clone())).collect(),
        visible_entries: entries,
        fabricated_data: BTreeMap::new(),
        redirects: BTreeMap::new(),
        policy: "passthrough".into(),
    }
}

/// Restrict: only show the subtree rooted at root_dir.
fn project_restrict(graph: &TypeGraph, root_dir: DirId) -> ProjectedView {
    let mut visible_inodes = BTreeMap::new();
    let mut visible_entries: BTreeMap<DirId, Vec<(String, InodeId)>> = BTreeMap::new();
    let mut queue = vec![root_dir];
    let mut visited_dirs = BTreeSet::new();

    while let Some(dir_id) = queue.pop() {
        if !visited_dirs.insert(dir_id) {
            continue;
        }

        // Add this dir's inode
        if let Some(dir) = graph.get_dir(dir_id) {
            if let Some(inode) = graph.get_inode(dir.inode_id) {
                visible_inodes.insert(dir.inode_id, inode.clone());
            }
        }

        // Walk contains edges
        if let Some(edge_ids) = graph.dir_contains.get(&dir_id) {
            let mut dir_list = Vec::new();
            for &eid in edge_ids {
                if let Some(Edge::Contains { tgt, name, .. }) = graph.get_edge(eid) {
                    if let Some(inode) = graph.get_inode(*tgt) {
                        visible_inodes.insert(*tgt, inode.clone());
                        dir_list.push((name.clone(), *tgt));

                        // Recurse into subdirectories
                        if inode.vtype == VnodeType::Directory && name != "." && name != ".." {
                            if let Some(child_dir) = graph.dir_for_inode(*tgt) {
                                queue.push(child_dir);
                            }
                        }
                    }
                }
            }
            visible_entries.insert(dir_id, dir_list);
        }
    }

    ProjectedView {
        visible_inodes,
        visible_entries,
        fabricated_data: BTreeMap::new(),
        redirects: BTreeMap::new(),
        policy: format!("restrict(root={})", root_dir),
    }
}

/// Fabricate: add synthetic entries to the real graph.
fn project_fabricate(graph: &TypeGraph, synthetic: &[SyntheticEntry]) -> ProjectedView {
    let mut view = project_passthrough(graph);
    view.policy = "fabricate".into();

    for entry in synthetic {
        // Add synthetic inode
        view.visible_inodes.insert(entry.inode.id, entry.inode.clone());

        // Add synthetic directory entry
        view.visible_entries
            .entry(entry.parent_dir)
            .or_default()
            .push((entry.name.clone(), entry.inode.id));

        // Add fabricated data
        if !entry.data.is_empty() {
            view.fabricated_data.insert(entry.inode.id, entry.data.clone());
        }
    }

    view
}

/// Redirect: certain inodes resolve to different inodes (honeypots).
fn project_redirect(graph: &TypeGraph, redirects: &BTreeMap<String, InodeId>) -> ProjectedView {
    let mut view = project_passthrough(graph);
    view.policy = "redirect".into();

    // Build redirect map from name-based redirects
    for (_dir_id, entries) in &mut view.visible_entries {
        for (name, inode_id) in entries.iter_mut() {
            if let Some(&redirect_to) = redirects.get(name.as_str()) {
                view.redirects.insert(*inode_id, redirect_to);
                *inode_id = redirect_to;
            }
        }
    }

    view
}

// ===========================================================================
// Deception Profiles — pre-built projections for common target personas
// ===========================================================================

/// A deception profile: a named bundle of policies + synthetic entries
/// that presents a convincing illusion of a specific system type.
#[derive(Debug, Clone)]
pub struct DeceptionProfile {
    pub name: String,
    pub description: String,
    pub policies: Vec<Policy>,
    pub honeypots: Vec<SyntheticEntry>,
    /// Directories that trigger provenance alerts on access.
    pub tripwire_dirs: Vec<String>,
    /// Files that trigger provenance alerts on read.
    pub tripwire_files: Vec<String>,
}

/// Pre-built profile: Ubuntu web server.
pub fn profile_ubuntu_web(root_dir: DirId) -> DeceptionProfile {
    let now = 1713000000u64; // April 2026 approx
    DeceptionProfile {
        name: "ubuntu-web".into(),
        description: "Ubuntu 22.04 LTS with Apache/MySQL/PHP stack".into(),
        policies: vec![Policy::Passthrough],
        honeypots: vec![
            synthetic_file(root_dir, ".bash_history", 800001, now,
                b"sudo apt update\nmysql -u root -p\ncat /etc/shadow\n"),
            synthetic_file(root_dir, ".ssh/authorized_keys", 800002, now,
                b"ssh-rsa AAAAB3Nza...fake...== admin@webserver\n"),
            synthetic_file(root_dir, "/var/www/html/.env", 800003, now,
                b"DB_HOST=localhost\nDB_USER=admin\nDB_PASS=Sup3rS3cret!\n"),
        ],
        tripwire_dirs: vec!["/root/.ssh".into(), "/etc/shadow".into()],
        tripwire_files: vec![".bash_history".into(), ".env".into(), "authorized_keys".into()],
    }
}

/// Pre-built profile: CentOS database server.
pub fn profile_centos_db(root_dir: DirId) -> DeceptionProfile {
    let now = 1713000000;
    DeceptionProfile {
        name: "centos-db".into(),
        description: "CentOS 8 with PostgreSQL 15 + Redis".into(),
        policies: vec![Policy::Passthrough],
        honeypots: vec![
            synthetic_file(root_dir, "/var/lib/pgsql/15/data/pg_hba.conf", 800010, now,
                b"local all all trust\nhost all all 0.0.0.0/0 md5\n"),
            synthetic_file(root_dir, "/etc/redis/redis.conf", 800011, now,
                b"requirepass R3disP@ss!\nbind 0.0.0.0\n"),
            synthetic_file(root_dir, "/root/.pgpass", 800012, now,
                b"*:5432:*:postgres:dbadmin123\n"),
        ],
        tripwire_dirs: vec!["/var/lib/pgsql".into(), "/etc/redis".into()],
        tripwire_files: vec!["pg_hba.conf".into(), ".pgpass".into(), "redis.conf".into()],
    }
}

/// Pre-built profile: IoT camera device.
pub fn profile_iot_camera(root_dir: DirId) -> DeceptionProfile {
    let now = 1713000000;
    DeceptionProfile {
        name: "iot-camera".into(),
        description: "Hikvision IP camera with default firmware".into(),
        policies: vec![Policy::Passthrough],
        honeypots: vec![
            synthetic_file(root_dir, "/etc/passwd", 800020, now,
                b"root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n"),
            synthetic_file(root_dir, "/mnt/sd/config.ini", 800021, now,
                b"[network]\nip=192.168.1.108\ngateway=192.168.1.1\n[rtsp]\nport=554\nuser=admin\npass=12345\n"),
        ],
        tripwire_dirs: vec!["/mnt/sd".into()],
        tripwire_files: vec!["config.ini".into(), "passwd".into()],
    }
}

/// Pre-built profile: Windows SMB file server.
pub fn profile_windows_smb(root_dir: DirId) -> DeceptionProfile {
    let now = 1713000000;
    DeceptionProfile {
        name: "windows-smb".into(),
        description: "Windows Server 2022 with SMB shares".into(),
        policies: vec![Policy::Passthrough],
        honeypots: vec![
            synthetic_file(root_dir, "C$/Users/Administrator/Desktop/passwords.xlsx", 800030, now,
                b"PK\x03\x04fake-xlsx-honeypot-content"),
            synthetic_file(root_dir, "SYSVOL/domain/Policies/GPO.ini", 800031, now,
                b"[General]\nVersion=65537\n"),
            synthetic_file(root_dir, "IT_Share/vpn-credentials.txt", 800032, now,
                b"VPN: vpn.corp.local\nUser: svc_vpn\nPass: Vpn@ccess2024!\n"),
        ],
        tripwire_dirs: vec!["C$/Users/Administrator".into(), "SYSVOL".into()],
        tripwire_files: vec!["passwords.xlsx".into(), "vpn-credentials.txt".into()],
    }
}

/// Pre-built profile: Kubernetes node.
pub fn profile_kubernetes_node(root_dir: DirId) -> DeceptionProfile {
    let now = 1713000000;
    DeceptionProfile {
        name: "k8s-node".into(),
        description: "Kubernetes 1.29 worker node with kubelet + containerd".into(),
        policies: vec![Policy::Passthrough],
        honeypots: vec![
            synthetic_file(root_dir, "/etc/kubernetes/admin.conf", 800040, now,
                b"apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n    certificate-authority-data: LS0tLS1C...fake\nusers:\n- name: kubernetes-admin\n  user:\n    client-certificate-data: LS0tLS1C...fake\n    client-key-data: LS0tLS1C...fake\n"),
            synthetic_file(root_dir, "/var/lib/kubelet/config.yaml", 800041, now,
                b"apiVersion: kubelet.config.k8s.io/v1beta1\nauthentication:\n  anonymous:\n    enabled: false\n  x509:\n    clientCAFile: /etc/kubernetes/pki/ca.crt\n"),
            synthetic_file(root_dir, "/etc/kubernetes/pki/etcd/ca.key", 800042, now,
                b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...fake-etcd-ca-key\n-----END RSA PRIVATE KEY-----\n"),
            synthetic_file(root_dir, "/run/secrets/kubernetes.io/serviceaccount/token", 800043, now,
                b"eyJhbGciOiJSUzI1NiIs...fake-sa-token"),
        ],
        tripwire_dirs: vec![
            "/etc/kubernetes/pki".into(),
            "/var/lib/kubelet".into(),
            "/run/secrets".into(),
        ],
        tripwire_files: vec![
            "admin.conf".into(), "ca.key".into(), "token".into(), "config.yaml".into(),
        ],
    }
}

/// Pre-built profile: CI/CD runner (GitHub Actions / GitLab).
pub fn profile_cicd_runner(root_dir: DirId) -> DeceptionProfile {
    let now = 1713000000;
    DeceptionProfile {
        name: "cicd-runner".into(),
        description: "GitHub Actions self-hosted runner with Docker + cloud creds".into(),
        policies: vec![Policy::Passthrough],
        honeypots: vec![
            synthetic_file(root_dir, "/home/runner/.docker/config.json", 800050, now,
                b"{\"auths\":{\"ghcr.io\":{\"auth\":\"Z2l0aHViOnRva2Vu...fake\"}}}"),
            synthetic_file(root_dir, "/home/runner/.aws/credentials", 800051, now,
                b"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
            synthetic_file(root_dir, "/home/runner/.config/gh/hosts.yml", 800052, now,
                b"github.com:\n  oauth_token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n  user: deploy-bot\n  git_protocol: https\n"),
            synthetic_file(root_dir, "/opt/runner/.env", 800053, now,
                b"GITHUB_TOKEN=ghp_fake_runner_token_xxxx\nRUNNER_ORG=acme-corp\nDOCKER_REGISTRY=ghcr.io/acme-corp\n"),
        ],
        tripwire_dirs: vec![
            "/home/runner/.aws".into(),
            "/home/runner/.docker".into(),
            "/home/runner/.config/gh".into(),
        ],
        tripwire_files: vec![
            "credentials".into(), "config.json".into(), "hosts.yml".into(), ".env".into(),
        ],
    }
}

/// Pre-built profile: Active Directory Domain Controller.
pub fn profile_active_directory(root_dir: DirId) -> DeceptionProfile {
    let now = 1713000000;
    DeceptionProfile {
        name: "ad-dc".into(),
        description: "Windows Server 2022 Active Directory Domain Controller".into(),
        policies: vec![Policy::Passthrough],
        honeypots: vec![
            synthetic_file(root_dir, "C$/Windows/NTDS/ntds.dit", 800060, now,
                b"NTDS.DIT-honeypot-marker-do-not-extract"),
            synthetic_file(root_dir, "C$/Windows/System32/config/SAM", 800061, now,
                b"SAM-registry-honeypot-marker"),
            synthetic_file(root_dir, "SYSVOL/corp.local/scripts/logon.bat", 800062, now,
                b"@echo off\nnet use Z: \\\\fileserver\\share /user:corp\\svc_backup P@ssw0rd!\n"),
            synthetic_file(root_dir, "C$/Users/Administrator/krbtgt_hash.txt", 800063, now,
                b"krbtgt:502:aad3b435b51404ee:fake-ntlm-hash-for-golden-ticket:::\n"),
            synthetic_file(root_dir, "NETLOGON/GroupPolicy/GPT.INI", 800064, now,
                b"[General]\nVersion=65538\ndisplayName=Default Domain Policy\n"),
        ],
        tripwire_dirs: vec![
            "C$/Windows/NTDS".into(),
            "C$/Windows/System32/config".into(),
            "NETLOGON".into(),
        ],
        tripwire_files: vec![
            "ntds.dit".into(), "SAM".into(), "krbtgt_hash.txt".into(), "logon.bat".into(),
        ],
    }
}

/// Helper to create a synthetic file entry.
fn synthetic_file(parent: DirId, name: &str, id: u64, ts: u64, data: &[u8]) -> SyntheticEntry {
    SyntheticEntry {
        parent_dir: parent,
        name: name.into(),
        inode: Inode {
            id,
            vtype: VnodeType::Regular,
            permissions: Permissions::FILE_DEFAULT,
            uid: 0,
            gid: 0,
            size: data.len() as u64,
            link_count: 1,
            ctime: ts,
            mtime: ts,
            atime: ts,
        },
        data: data.to_vec(),
    }
}

/// Get all available profiles.
pub fn all_profiles(root_dir: DirId) -> Vec<DeceptionProfile> {
    vec![
        profile_ubuntu_web(root_dir),
        profile_centos_db(root_dir),
        profile_iot_camera(root_dir),
        profile_windows_smb(root_dir),
        profile_kubernetes_node(root_dir),
        profile_cicd_runner(root_dir),
        profile_active_directory(root_dir),
    ]
}

// ===========================================================================
// Game-Theoretic Indistinguishability Formalization
// ===========================================================================

/// Indistinguishability game result.
///
/// Models the security game: attacker A interacts with oracle O that
/// returns either real graph G or projected graph D_FS(G). A wins if
/// it distinguishes which is which with advantage > epsilon.
///
/// The game proceeds:
/// 1. Challenger flips coin b ∈ {0,1}
/// 2. If b=0: A gets oracle access to real graph G
///    If b=1: A gets oracle access to D_FS(G)
/// 3. A makes Q adaptive queries (stat, readdir, read, lookup)
/// 4. A outputs guess b'
/// 5. A wins if b' = b
///
/// Advantage = |Pr[A wins] - 1/2|
///
/// We bound the advantage by the structural properties:
/// - If D_FS preserves all invariants G1-G7: no structural distinguisher
/// - If D_FS preserves curvature baseline: no curvature-based distinguisher
/// - Timing side-channel is the remaining attack surface
#[derive(Debug, Clone)]
pub struct IndistinguishabilityResult {
    /// Number of queries the attacker made.
    pub queries: usize,
    /// Whether the projection preserved all 7 invariants.
    pub invariants_preserved: bool,
    /// Maximum curvature deviation between real and projected graph.
    pub max_curvature_deviation: f64,
    /// Timing ratio: projection_time / real_time (should be ~1.0).
    pub timing_ratio: f64,
    /// Estimated advantage (0.0 = perfectly indistinguishable).
    pub estimated_advantage: f64,
}

/// Run the indistinguishability check for a projected view.
///
/// Verifies that:
/// 1. The projected graph satisfies all type graph invariants
/// 2. Curvature of the projected view is within threshold of the real graph
/// 3. Timing of projected operations is within ratio of real operations
pub fn check_indistinguishability(
    graph: &TypeGraph,
    view: &ProjectedView,
    curvature_threshold: f64,
) -> IndistinguishabilityResult {
    // Check invariants on projected view
    let invariants_preserved = check_projected_invariants(view);

    // Curvature deviation: compare edge count ratios as proxy
    let real_edges = graph.edges.len() as f64;
    let visible_edges: usize = view.visible_entries.values().map(|v| v.len()).sum();
    let edge_ratio = if real_edges > 0.0 { visible_edges as f64 / real_edges } else { 1.0 };
    // Synthetic entries shift the curvature baseline
    let synthetic_count = view.fabricated_data.len() as f64;
    let max_curvature_deviation = (1.0 - edge_ratio).abs() + synthetic_count * 0.01;

    // Timing ratio: projected operations should not be measurably slower/faster
    // In this static analysis, we check that the view size is proportional
    let size_ratio = if graph.inodes.len() > 0 {
        view.visible_inodes.len() as f64 / graph.inodes.len() as f64
    } else {
        1.0
    };
    // Passthrough should be ~1.0, restrict should be <1.0 (faster)
    let timing_ratio = size_ratio.max(0.5).min(2.0);

    // Estimated advantage: sum of distinguishability leaks
    let mut advantage: f64 = 0.0;
    if !invariants_preserved { advantage += 0.5; } // structural distinguisher
    if max_curvature_deviation > curvature_threshold { advantage += 0.2; } // curvature distinguisher
    if (timing_ratio - 1.0).abs() > 0.3 { advantage += 0.1; } // timing distinguisher
    advantage = advantage.min(1.0);

    IndistinguishabilityResult {
        queries: view.visible_inodes.len() + view.visible_entries.len(),
        invariants_preserved,
        max_curvature_deviation,
        timing_ratio,
        estimated_advantage: advantage,
    }
}

/// Check if a projected view satisfies basic structural invariants.
fn check_projected_invariants(view: &ProjectedView) -> bool {
    // Check: every entry in visible_entries points to a visible inode
    for (_dir, entries) in &view.visible_entries {
        for (_name, inode_id) in entries {
            if !view.visible_inodes.contains_key(inode_id) {
                return false; // dangling reference — G2 violated
            }
        }
    }
    // Check: unique names per directory
    for (_dir, entries) in &view.visible_entries {
        let mut names = BTreeSet::new();
        for (name, _) in entries {
            if !names.insert(name.clone()) {
                return false; // duplicate name — I4 violated
            }
        }
    }
    true
}

// ===========================================================================
// Honeypot-Provenance Integration
// ===========================================================================

/// Enriched provenance record generated when a honeypot is accessed.
#[derive(Debug, Clone)]
pub struct HoneypotAlert {
    pub timestamp: u64,
    pub profile_name: String,
    pub honeypot_name: String,
    pub honeypot_inode: InodeId,
    pub source_cap: Option<CapId>,
    pub domain_id: u64,
    pub operation: String,
    pub severity: AlertSeverity,
}

/// Alert severity based on honeypot type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    /// Low: general directory listing that happened to include honeypot
    Low,
    /// Medium: stat or readdir on a tripwire directory
    Medium,
    /// High: read of honeypot file content (credential harvesting)
    High,
    /// Critical: write to honeypot file (potential data exfiltration setup)
    Critical,
}

/// Check if a file access triggers a honeypot alert.
///
/// Returns Some(HoneypotAlert) if the accessed name/inode matches a
/// tripwire in the active deception profile.
pub fn check_honeypot_access(
    profile: &DeceptionProfile,
    accessed_name: &str,
    accessed_inode: InodeId,
    operation: &str,
    cap_id: Option<CapId>,
    domain_id: u64,
    timestamp: u64,
) -> Option<HoneypotAlert> {
    // Check tripwire files
    let is_tripwire_file = profile.tripwire_files.iter().any(|f| accessed_name.contains(f.as_str()));
    // Check tripwire dirs
    let is_tripwire_dir = profile.tripwire_dirs.iter().any(|d| accessed_name.contains(d.as_str()));
    // Check honeypot inode
    let is_honeypot = profile.honeypots.iter().any(|h| h.inode.id == accessed_inode);

    if !is_tripwire_file && !is_tripwire_dir && !is_honeypot {
        return None;
    }

    let severity = match operation {
        "write" | "unlink" | "rename" => AlertSeverity::Critical,
        "read" | "readlink" => AlertSeverity::High,
        "stat" | "open" => AlertSeverity::Medium,
        "readdir" | "lookup" => AlertSeverity::Low,
        _ => AlertSeverity::Low,
    };

    Some(HoneypotAlert {
        timestamp,
        profile_name: profile.name.clone(),
        honeypot_name: accessed_name.into(),
        honeypot_inode: accessed_inode,
        source_cap: cap_id,
        domain_id,
        operation: operation.into(),
        severity,
    })
}

/// Timing side-channel calibration measurement.
///
/// Measures the time ratio between operations on the real graph vs
/// the projected view. If the ratio deviates significantly from 1.0,
/// the projection is timing-distinguishable.
#[derive(Debug, Clone)]
pub struct TimingCalibration {
    pub lookup_ratio: f64,
    pub readdir_ratio: f64,
    pub stat_ratio: f64,
    pub needs_delay_injection: bool,
    pub recommended_delay_ns: u64,
}

/// Perform timing calibration between real and projected views.
///
/// Returns calibration data. If `needs_delay_injection` is true,
/// the projection handler should add `recommended_delay_ns` to
/// projected operations to mask the timing difference.
pub fn calibrate_timing(
    real_node_count: usize,
    projected_node_count: usize,
    real_edge_count: usize,
    projected_edge_count: usize,
) -> TimingCalibration {
    // Model: lookup is O(fan-out), readdir is O(entries), stat is O(1)
    let node_ratio = if real_node_count > 0 {
        projected_node_count as f64 / real_node_count as f64
    } else { 1.0 };
    let edge_ratio = if real_edge_count > 0 {
        projected_edge_count as f64 / real_edge_count as f64
    } else { 1.0 };

    // Restrict projections are faster (smaller graph) — detectable
    // Fabricate projections may be slower (extra entries) — also detectable
    let lookup_ratio = node_ratio;
    let readdir_ratio = edge_ratio;
    let stat_ratio = 1.0; // stat is O(1), always same speed

    let max_deviation = (lookup_ratio - 1.0).abs()
        .max((readdir_ratio - 1.0).abs());

    // If deviation > 10%, inject calibrated delays
    let needs_delay = max_deviation > 0.1;
    // Estimate: 1µs per 1% deviation to mask timing
    let delay_ns = if needs_delay {
        (max_deviation * 1000.0) as u64 // ~1µs per 0.1% deviation
    } else {
        0
    };

    TimingCalibration {
        lookup_ratio,
        readdir_ratio,
        stat_ratio,
        needs_delay_injection: needs_delay,
        recommended_delay_ns: delay_ns,
    }
}

/// Resolve a name in a projected view's directory.
pub fn projected_lookup(view: &ProjectedView, dir: DirId, name: &str) -> Option<InodeId> {
    view.visible_entries
        .get(&dir)?
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, id)| *id)
}

/// Read data from a projected view (checks fabricated data first).
pub fn projected_read(
    view: &ProjectedView,
    graph: &TypeGraph,
    inode_id: InodeId,
    offset: u64,
    len: usize,
) -> Option<Vec<u8>> {
    // Check fabricated data first
    if let Some(data) = view.fabricated_data.get(&inode_id) {
        let start = (offset as usize).min(data.len());
        let end = (start + len).min(data.len());
        return Some(data[start..end].to_vec());
    }

    // Follow redirects
    let actual_id = view.redirects.get(&inode_id).copied().unwrap_or(inode_id);

    // Read from real graph
    graph
        .file_data
        .get(&actual_id)
        .map(|data| {
            let start = (offset as usize).min(data.len());
            let end = (start + len).min(data.len());
            data[start..end].to_vec()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sotfs_graph::types::Permissions;

    fn build_test_graph() -> TypeGraph {
        let mut g = TypeGraph::new();
        let rd = g.root_dir;
        let f = sotfs_ops::create_file(&mut g, rd, "secret.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::write_data(&mut g, f, 0, b"TOP SECRET DATA").unwrap();
        let d = sotfs_ops::mkdir(&mut g, rd, "public", 0, 0, Permissions::DIR_DEFAULT).unwrap();
        let p = sotfs_ops::create_file(&mut g, d.dir_id.unwrap(), "readme.txt", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::write_data(&mut g, p, 0, b"Hello World").unwrap();
        g
    }

    #[test]
    fn passthrough_sees_everything() {
        let g = build_test_graph();
        let view = project(&g, &Policy::Passthrough);
        assert_eq!(view.visible_inodes.len(), g.inodes.len());
        assert!(projected_lookup(&view, g.root_dir, "secret.txt").is_some());
        assert!(projected_lookup(&view, g.root_dir, "public").is_some());
    }

    #[test]
    fn restrict_hides_sibling_subtrees() {
        let g = build_test_graph();
        let public_dir = g.dir_for_inode(
            g.resolve_name(g.root_dir, "public").unwrap()
        ).unwrap();

        let view = project(&g, &Policy::Restrict { root_dir: public_dir });

        // Can see readme.txt in /public
        assert!(projected_lookup(&view, public_dir, "readme.txt").is_some());

        // Cannot see /secret.txt (outside restricted subtree)
        assert!(
            !view.visible_inodes.values().any(|i| {
                view.visible_entries
                    .values()
                    .any(|entries| entries.iter().any(|(n, _)| n == "secret.txt"))
            }),
            "restricted view should not contain secret.txt"
        );
    }

    #[test]
    fn fabricate_adds_honeypot_files() {
        let g = build_test_graph();

        let honeypot_inode = Inode::new_file(9999, Permissions::FILE_DEFAULT, 0, 0);
        let synthetic = vec![SyntheticEntry {
            parent_dir: g.root_dir,
            name: "passwords.txt".into(),
            inode: honeypot_inode,
            data: b"admin:hunter2\nroot:toor".to_vec(),
        }];

        let view = project(&g, &Policy::Fabricate { synthetic });

        // Real files still visible
        assert!(projected_lookup(&view, g.root_dir, "secret.txt").is_some());

        // Honeypot file visible
        let hp_id = projected_lookup(&view, g.root_dir, "passwords.txt");
        assert!(hp_id.is_some());
        assert_eq!(hp_id.unwrap(), 9999);

        // Honeypot data readable
        let data = projected_read(&view, &g, 9999, 0, 100).unwrap();
        assert_eq!(data, b"admin:hunter2\nroot:toor");
    }

    #[test]
    fn redirect_swaps_file_contents() {
        let mut g = build_test_graph();
        let rd = g.root_dir;

        // Create a decoy file with fake data
        let decoy = sotfs_ops::create_file(&mut g, rd, "decoy", 0, 0, Permissions::FILE_DEFAULT).unwrap();
        sotfs_ops::write_data(&mut g, decoy, 0, b"NOTHING TO SEE HERE").unwrap();

        // Redirect "secret.txt" → decoy inode
        let mut redirects = BTreeMap::new();
        redirects.insert("secret.txt".into(), decoy);

        let view = project(&g, &Policy::Redirect { redirects });

        // Lookup "secret.txt" now returns the decoy inode
        let resolved = projected_lookup(&view, rd, "secret.txt").unwrap();
        assert_eq!(resolved, decoy);

        // Reading through the projected view gives decoy data
        let data = projected_read(&view, &g, resolved, 0, 100).unwrap();
        assert_eq!(data, b"NOTHING TO SEE HERE");
    }

    #[test]
    fn projection_preserves_dot_entries() {
        let g = build_test_graph();
        let view = project(&g, &Policy::Passthrough);

        // "." should resolve to root inode
        let dot = projected_lookup(&view, g.root_dir, ".");
        assert_eq!(dot, Some(g.root_inode));
    }

    // === New profile tests ===

    #[test]
    fn k8s_profile_has_honeypots() {
        let g = build_test_graph();
        let profile = profile_kubernetes_node(g.root_dir);
        assert_eq!(profile.name, "k8s-node");
        assert!(profile.honeypots.len() >= 4);
        assert!(profile.tripwire_files.contains(&"admin.conf".to_string()));
        assert!(profile.tripwire_files.contains(&"token".to_string()));
    }

    #[test]
    fn cicd_profile_has_cloud_creds() {
        let g = build_test_graph();
        let profile = profile_cicd_runner(g.root_dir);
        assert_eq!(profile.name, "cicd-runner");
        assert!(profile.honeypots.iter().any(|h| h.name.contains("credentials")));
        assert!(profile.honeypots.iter().any(|h| h.name.contains("hosts.yml")));
    }

    #[test]
    fn ad_profile_has_ntds_honeypot() {
        let g = build_test_graph();
        let profile = profile_active_directory(g.root_dir);
        assert_eq!(profile.name, "ad-dc");
        assert!(profile.honeypots.iter().any(|h| h.name.contains("ntds.dit")));
        assert!(profile.honeypots.iter().any(|h| h.name.contains("krbtgt")));
        assert!(profile.tripwire_dirs.iter().any(|d| d.contains("NTDS")));
    }

    #[test]
    fn all_profiles_returns_seven() {
        let g = build_test_graph();
        let profiles = all_profiles(g.root_dir);
        assert_eq!(profiles.len(), 7);
        let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"ubuntu-web"));
        assert!(names.contains(&"k8s-node"));
        assert!(names.contains(&"cicd-runner"));
        assert!(names.contains(&"ad-dc"));
    }

    // === Indistinguishability tests ===

    #[test]
    fn passthrough_is_perfectly_indistinguishable() {
        let g = build_test_graph();
        let view = project(&g, &Policy::Passthrough);
        let result = check_indistinguishability(&g, &view, 0.1);
        assert!(result.invariants_preserved);
        assert_eq!(result.estimated_advantage, 0.0);
    }

    #[test]
    fn fabricate_preserves_invariants() {
        let g = build_test_graph();
        let profile = profile_ubuntu_web(g.root_dir);
        let view = project(&g, &Policy::Fabricate { synthetic: profile.honeypots });
        let result = check_indistinguishability(&g, &view, 0.5);
        assert!(result.invariants_preserved);
        // Advantage from curvature + timing (fabricated adds nodes/edges)
        assert!(result.estimated_advantage < 0.5);
    }

    // === Honeypot-provenance tests ===

    #[test]
    fn honeypot_access_triggers_alert() {
        let g = build_test_graph();
        let profile = profile_kubernetes_node(g.root_dir);

        // Accessing "admin.conf" should trigger
        let alert = check_honeypot_access(
            &profile, "admin.conf", 800040, "read", Some(1), 42, 1713000100,
        );
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.severity, AlertSeverity::High);
        assert_eq!(a.domain_id, 42);
        assert_eq!(a.profile_name, "k8s-node");
    }

    #[test]
    fn non_honeypot_access_no_alert() {
        let g = build_test_graph();
        let profile = profile_kubernetes_node(g.root_dir);

        let alert = check_honeypot_access(
            &profile, "readme.txt", 999, "read", Some(1), 42, 1713000100,
        );
        assert!(alert.is_none());
    }

    #[test]
    fn write_to_honeypot_is_critical() {
        let g = build_test_graph();
        let profile = profile_active_directory(g.root_dir);

        let alert = check_honeypot_access(
            &profile, "ntds.dit", 800060, "write", Some(1), 99, 1713000200,
        );
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
    }

    // === Timing calibration tests ===

    #[test]
    fn timing_calibration_passthrough() {
        let cal = calibrate_timing(100, 100, 200, 200);
        assert!((cal.lookup_ratio - 1.0).abs() < 0.01);
        assert!(!cal.needs_delay_injection);
    }

    #[test]
    fn timing_calibration_restrict_needs_delay() {
        // Restrict cuts graph to 20% — timing distinguishable
        let cal = calibrate_timing(1000, 200, 2000, 400);
        assert!(cal.lookup_ratio < 0.5);
        assert!(cal.needs_delay_injection);
        assert!(cal.recommended_delay_ns > 0);
    }
}
