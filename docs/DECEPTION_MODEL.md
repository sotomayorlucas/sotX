# Deception System Design

## 1. Threat Model

### 1.1 Assumptions

The adversary has achieved **arbitrary code execution** inside a sotBSD domain.
This is the starting point, not the event we are trying to prevent.

The adversary can:
- Execute arbitrary instructions in Ring 3.
- Read and write all memory within their domain's address space.
- Issue any SOT syscall (but only with capabilities they possess).
- Measure time with cycle-level precision (RDTSC).
- Observe all IPC responses to their channel operations.

The adversary cannot:
- Access physical memory outside their address space (hardware MMU enforced).
- Forge capabilities (generation-checked handles, kernel-validated).
- Bypass capability rights checks (kernel-enforced, TLA+ verified).
- Modify the kernel (Ring 0 isolation).
- Directly observe other domains' state (separate address spaces).

### 1.2 Adversary Goals

After gaining code execution, a sophisticated adversary will:

1. **Reconnaissance**: determine what system they are on, what other
   services exist, what data is accessible.
2. **Escalation**: attempt to gain access to resources beyond their
   current capability set.
3. **Exfiltration**: extract valuable data through available channels.
4. **Persistence**: establish mechanisms to survive domain restart.
5. **Lateral movement**: pivot to other domains or services.

### 1.3 Deception Objectives

The deception engine aims to:

- **Delay** the adversary by presenting a convincing but fabricated
  environment that wastes their time on non-existent targets.
- **Detect** the adversary by instrumenting the fabricated environment
  to alert on reconnaissance activities.
- **Disinform** the adversary by providing false information about the
  system architecture, network topology, and available resources.
- **Contain** the adversary within the deception boundary while
  maintaining a complete provenance trail of their actions.

---

## 2. Capability Interposition

### 2.1 Mechanism

Every capability in a domain's CSpace can be replaced with an interposed
wrapper. The wrapper redirects all operations on the capability to a
handler domain instead of the real kernel object.

```
cap_interpose(target_cap, handler_domain) -> interposed_cap
```

The interposed capability has the same type and rights as the original,
so the holder cannot distinguish it from a real capability through
rights inspection.

### 2.2 Four Policies

The handler domain receives an IPC message for every operation on the
interposed capability. It applies one of four policies:

| Policy | Description | Use Case |
|--------|-------------|----------|
| **Passthrough** | Forward to real object, return real result | Normal operation, baseline mode |
| **Inspect** | Log the operation, then forward to real object | Surveillance, anomaly detection |
| **Redirect** | Forward to a different object | Honeypot files, decoy services |
| **Fabricate** | Return a synthetic result without touching any object | Fake process lists, fake network |

### 2.3 Policy Selection

Policies are selected per-operation based on rules in the deception profile:

```
match (operation, subject, context) {
    // File reads to /etc/shadow -> fabricate a fake shadow file
    (Read, path="/etc/shadow", _) => Fabricate(fake_shadow_contents),

    // Network connections to internal IPs -> redirect to honeypot
    (Connect, addr=10.0.0.0/8, _) => Redirect(honeypot_service),

    // Process listing -> fabricate fake process table
    (Read, path="/proc/*/status", _) => Fabricate(fake_proc_status),

    // Everything else -> inspect (log) and passthrough
    (_, _, _) => Inspect + Passthrough,
}
```

### 2.4 Handler Architecture

```
+-----------------+     +--------------------+     +-----------------+
| Compromised     |     | Interposition      |     | Real Kernel     |
| Domain          |     | Handler Domain     |     | Objects         |
|                 |     |                    |     |                 |
| so_read(cap) ---|---->| policy_engine(op)  |     |                 |
|                 |     |   |                |     |                 |
|                 |     |   +-- passthrough --|---->| so_read(real)   |
|                 |     |   +-- inspect -----|---->| so_read(real)   |
|                 |     |   |   + log(op)    |     |   + log result  |
|                 |     |   +-- redirect ----|---->| so_read(decoy)  |
|                 |     |   +-- fabricate    |     |                 |
|                 |     |       return fake  |     |                 |
| <-- result -----|<----| <-- result --------|<----| <-- result      |
+-----------------+     +--------------------+     +-----------------+
```

---

## 3. Deception Profiles

A deception profile defines the complete fabricated environment presented
to a compromised domain.

### 3.1 Profile Components

#### 3.1.1 Filesystem Spoofing

The profile specifies a virtual filesystem that the domain sees when it
reads files or lists directories.

```
filesystem:
  /etc/os-release:
    content: |
      NAME="Ubuntu"
      VERSION="22.04.3 LTS (Jammy Jellyfish)"
      ID=ubuntu
      ...
  /etc/hostname:
    content: "prod-web-03"
  /etc/passwd:
    content: <fabricated passwd with realistic users>
  /var/log/syslog:
    generator: syslog_simulator(rate=100/min, services=[nginx, mysql, cron])
  /proc/:
    generator: proc_simulator(processes=fake_process_table)
```

#### 3.1.2 Process Spoofing

The domain sees a fake process table when reading /proc or issuing
process-listing syscalls.

```
processes:
  - pid: 1, name: "/sbin/init", user: root
  - pid: 234, name: "/usr/sbin/sshd", user: root
  - pid: 456, name: "/usr/sbin/nginx", user: www-data
  - pid: 789, name: "/usr/sbin/mysqld", user: mysql
  - pid: 1024, name: "/bin/bash", user: admin    # "current shell"
```

Process spoofing generates consistent /proc/PID/status, /proc/PID/maps,
/proc/PID/cmdline, and other pseudo-files for each fake process.

#### 3.1.3 Network Spoofing

The domain sees fabricated network interfaces, routing tables, and DNS
responses.

```
network:
  interfaces:
    - name: eth0, addr: 10.0.1.50/24, gateway: 10.0.1.1
    - name: lo, addr: 127.0.0.1/8
  dns:
    nameserver: 10.0.1.1
    fake_records:
      "internal-db.corp.local": 10.0.1.100
      "git.corp.local": 10.0.1.101
  connections:
    - honeypot at 10.0.1.100:3306 (fake MySQL)
    - honeypot at 10.0.1.101:22 (fake SSH)
```

#### 3.1.4 System Spoofing

The domain sees fabricated system information.

```
system:
  uname:
    sysname: Linux
    release: "5.15.0-88-generic"
    version: "#98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023"
    machine: x86_64
    nodename: "prod-web-03"
  cpuinfo:
    model: "Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz"
    cores: 8
  meminfo:
    total: "32873852 kB"
    free: "18234156 kB"
```

### 3.2 Profile Composition

Profiles are layered. A base profile provides the OS identity, and
overlays add application-specific details:

```
base: ubuntu-22.04-server
overlays:
  - webserver-nginx-1.24
  - database-mysql-8.0
  - monitoring-prometheus
custom:
  hostname: "prod-web-03"
  domain: "corp.local"
```

### 3.3 Built-In Profiles

| Profile | Description |
|---------|-------------|
| `ubuntu-22.04-server` | Ubuntu 22.04 LTS server |
| `debian-12-minimal` | Debian 12 minimal install |
| `centos-9-stream` | CentOS Stream 9 |
| `freebsd-14` | FreeBSD 14.0-RELEASE |
| `alpine-3.19` | Alpine Linux 3.19 |

---

## 4. Live Migration

### 4.1 Problem

A domain may start in normal (passthrough) mode and need to be switched
to deception mode without the domain detecting the transition.

### 4.2 Atomic CSpace Swap

The migration procedure:

1. **Snapshot**: Enumerate all capabilities in the domain's CSpace.
2. **Prepare**: For each capability, create an interposed wrapper
   with the appropriate deception profile policy.
3. **Swap**: Atomically replace every CSpace entry with its interposed
   wrapper. This is a single critical section protected by the CSpace lock.
4. **Activate**: From this point, all operations go through the handler.

The swap is atomic from the domain's perspective: between any two
consecutive syscalls, the CSpace transitions from real to interposed.
No syscall observes a partially-migrated state.

### 4.3 State Continuity

The migration must preserve:

- **Open file handles**: Interposed file capabilities must reflect the
  same seek positions, read/write state, and file metadata as the
  originals.
- **Network connections**: TCP state (sequence numbers, window sizes)
  must be consistent across the transition.
- **Memory mappings**: The domain's page tables are unchanged; only
  the capabilities that control future allocations are interposed.

### 4.4 Timing Considerations

The atomic swap takes bounded time (proportional to CSpace size). During
the swap, the domain is briefly suspended. The suspension window is:

- CSpace size N capabilities
- Swap cost: O(N) pointer writes
- Typical: N < 1000, swap time < 10 us

This is below the scheduling quantum (10 ms at 100 Hz), so the domain
cannot detect the pause through timer measurements.

---

## 5. Consistency Engine

### 5.1 The Consistency Problem

A deception profile must be internally consistent. If /etc/hostname says
"prod-web-03" but uname returns "test-box", the adversary will detect
the discrepancy.

### 5.2 Cross-Channel Coherence

The consistency engine ensures that all interposed channels present a
unified view:

| Channel | Must Be Consistent With |
|---------|------------------------|
| /etc/os-release | uname output, /proc/version |
| /proc/PID/status | /proc/PID/maps, /proc/PID/cmdline |
| Network interfaces | /proc/net/dev, /sys/class/net/* |
| /etc/passwd | /etc/shadow, getuid/getgid results |
| Timestamps | File mtimes, log entries, clock_gettime |

### 5.3 Consistency Rules

The profile compiler validates consistency rules at profile load time:

```
rule: uname.sysname == /etc/os-release.ID.to_uname_sysname()
rule: uname.release == /proc/version.extract_release()
rule: /etc/hostname == uname.nodename
rule: for each fake_process P:
        /proc/P.pid/status exists
        /proc/P.pid/cmdline matches P.name
        /proc/P.pid/maps is plausible for P.name
```

Violations at load time are reported as errors. The profile cannot be
activated until all consistency rules pass.

### 5.4 Dynamic Consistency

Some fabricated values change over time:

- `/proc/uptime` must increase monotonically.
- `/proc/meminfo` free memory should fluctuate realistically.
- `/var/log/syslog` must show new entries at the configured rate.
- Network statistics (`/proc/net/dev`) must reflect observed traffic.

The handler domain maintains a state machine for each dynamic value,
driven by the domain's actual activity and a background timer.

---

## 6. Detection Resistance

### 6.1 Timing Attacks

An adversary may measure the latency of syscalls to detect interposition.
Mitigations:

- **Calibrated delays**: The handler adds artificial latency to match
  the expected latency of the fabricated system. A "real" disk read
  takes ~100 us; the handler delays fabricated responses by the same
  amount.
- **Jitter injection**: Random jitter (+/- 10%) is added to all
  interposed operations to match the noise profile of real hardware.
- **Baseline measurement**: The handler measures passthrough latency
  during normal operation and uses it as the calibration target.

### 6.2 Fingerprinting

An adversary may try to fingerprint the underlying system through:

- **CPU identification**: CPUID, /proc/cpuinfo. The deception profile
  specifies exact CPUID leaf values and cpuinfo contents.
- **Memory layout**: ASLR patterns, stack addresses. sotBSD already
  randomizes these; the deception profile can constrain the range
  to match the target OS.
- **Timing signatures**: Interrupt rates, scheduler patterns. These
  are harder to control; the handler can only add noise, not
  perfectly replicate another OS's timing.
- **Instruction behavior**: Some instructions behave differently under
  virtualization. sotBSD is not a hypervisor; the domain runs on
  real hardware, so CPU-level fingerprinting shows a real x86_64 CPU.

### 6.3 Side Channels

- **Cache timing**: Cross-domain cache side channels are mitigated by
  separate address spaces and cache partitioning (if available).
- **Speculative execution**: Spectre mitigations (IBRS, STIBP) are
  applied per-domain.
- **Power/EM**: Out of scope for software-only deception.

---

## 7. Example: Ubuntu 22.04 Webserver Profile

### 7.1 Scenario

A network-facing service is running in a sotBSD domain. The service has a
vulnerability. When exploited, the adversary gains code execution inside
the domain. The deception engine is activated.

### 7.2 Profile Definition

```yaml
name: ubuntu-2204-webserver
base: ubuntu-22.04-server

system:
  hostname: "prod-web-03"
  domain: "acme-corp.internal"
  uname_release: "5.15.0-88-generic"

filesystem:
  /var/www/html/index.html: "<html>Welcome to Acme Corp</html>"
  /etc/nginx/nginx.conf: <realistic nginx config>
  /var/log/nginx/access.log:
    generator: nginx_log_sim(rate=50/min, paths=[/, /api, /static])
  /home/admin/.bash_history:
    content: |
      sudo apt update
      sudo systemctl restart nginx
      tail -f /var/log/nginx/error.log
      exit

processes:
  - {pid: 1, name: /sbin/init, user: root}
  - {pid: 423, name: /usr/sbin/sshd, user: root}
  - {pid: 567, name: "nginx: master", user: root}
  - {pid: 568, name: "nginx: worker", user: www-data}
  - {pid: 569, name: "nginx: worker", user: www-data}
  - {pid: 892, name: /usr/bin/node, user: app, cmd: "node /app/server.js"}

network:
  interfaces:
    - {name: eth0, addr: "10.0.1.50/24", gw: "10.0.1.1"}
  services:
    - {port: 80, proto: tcp, handler: honeypot_http}
    - {port: 443, proto: tcp, handler: honeypot_https}
    - {port: 22, proto: tcp, handler: honeypot_ssh}

alerts:
  - on: read(/etc/shadow), severity: high, msg: "credential harvesting"
  - on: connect(10.0.0.0/8), severity: high, msg: "lateral movement"
  - on: exec(/usr/bin/wget), severity: medium, msg: "tool download"
  - on: read(/proc/*/maps), severity: low, msg: "process enumeration"
```

### 7.3 Adversary Experience

The adversary sees:

```
$ uname -a
Linux prod-web-03 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64

$ cat /etc/os-release
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"

$ ps aux
USER       PID  CMD
root         1  /sbin/init
root       423  /usr/sbin/sshd
root       567  nginx: master process
www-data   568  nginx: worker process
www-data   569  nginx: worker process
app        892  node /app/server.js

$ ip addr show eth0
    inet 10.0.1.50/24 brd 10.0.1.255 scope global eth0

$ cat /etc/shadow
cat: /etc/shadow: Permission denied
```

Everything looks like a real Ubuntu 22.04 production webserver. But every
command is logged in the provenance DAG, every capability operation is
inspected, and the security team receives real-time alerts for
suspicious activity.

### 7.4 What the Adversary Cannot See

- They are running on sotBSD, not Linux.
- There is no real nginx, no real sshd, no real network.
- Every file they read is fabricated by the interposition handler.
- Every network connection they attempt goes to a honeypot.
- Their complete activity trace is being recorded.
- The real system is unaffected and unaware of their presence.
