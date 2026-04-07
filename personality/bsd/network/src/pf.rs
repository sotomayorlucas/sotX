//! PF firewall as capability interposer.
//!
//! The PF interposer sits between client domains and the real network
//! domain. Clients receive *proxied* network capabilities that route
//! through PF before reaching the real stack. PF evaluates rules in
//! order (first match wins, BSD semantics) and can pass, block,
//! redirect, or log traffic.
//!
//! Two advanced hooks:
//! - **Provenance-aware rules**: a rule can query the capability
//!   provenance graph to decide whether a domain should be allowed.
//! - **Deception mode**: domains flagged for deception are routed
//!   through a synthetic network that returns crafted responses.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};

/// Protocol selector for PF rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Any,
    Tcp,
    Udp,
    Icmp,
}

/// What to do when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Pass,
    Block,
    /// Redirect to a different destination.
    Redirect(SocketAddrV4),
    /// Pass but log the packet metadata.
    Log,
}

/// Traffic direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
    Both,
}

/// Match criteria for an address+port pair.
/// `None` means "any".
#[derive(Debug, Clone, Copy)]
pub struct AddrMatch {
    pub addr: Option<Ipv4Addr>,
    pub port: Option<u16>,
}

impl AddrMatch {
    pub const ANY: Self = Self {
        addr: None,
        port: None,
    };

    pub fn new(addr: Option<Ipv4Addr>, port: Option<u16>) -> Self {
        Self { addr, port }
    }

    fn matches(&self, target: &SocketAddrV4) -> bool {
        if let Some(a) = self.addr {
            if a != *target.ip() {
                return false;
            }
        }
        if let Some(p) = self.port {
            if p != target.port() {
                return false;
            }
        }
        true
    }
}

/// Domain identity tag (opaque id assigned by the capability system).
pub type DomainId = u64;

/// Provenance query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceVerdict {
    /// Domain's provenance chain is trusted.
    Trusted,
    /// Domain's provenance is unknown or untrusted.
    Untrusted,
}

/// Callback trait for provenance queries.
/// The PF interposer calls this to ask the capability system
/// about a domain's lineage.
pub trait ProvenanceOracle {
    fn query(&self, domain: DomainId) -> ProvenanceVerdict;
}

/// A single PF rule.
#[derive(Debug, Clone)]
pub struct PfRule {
    pub direction: Direction,
    pub proto: Proto,
    pub src: AddrMatch,
    pub dst: AddrMatch,
    pub action: Action,
    /// If set, rule only applies to packets from this domain.
    pub domain_filter: Option<DomainId>,
    /// If true, consult provenance oracle; block if untrusted.
    pub require_provenance: bool,
}

impl PfRule {
    /// Quick constructor for common rules.
    pub fn pass_all() -> Self {
        Self {
            direction: Direction::Both,
            proto: Proto::Any,
            src: AddrMatch::ANY,
            dst: AddrMatch::ANY,
            action: Action::Pass,
            domain_filter: None,
            require_provenance: false,
        }
    }

    pub fn block_all() -> Self {
        Self {
            direction: Direction::Both,
            proto: Proto::Any,
            src: AddrMatch::ANY,
            dst: AddrMatch::ANY,
            action: Action::Block,
            domain_filter: None,
            require_provenance: false,
        }
    }

    fn matches_direction(&self, dir: Direction) -> bool {
        self.direction == Direction::Both || self.direction == dir
    }

    fn matches_proto(&self, proto: Proto) -> bool {
        self.proto == Proto::Any || self.proto == proto
    }
}

/// Metadata about a packet being evaluated.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub direction: Direction,
    pub proto: Proto,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub domain: DomainId,
}

/// The result of evaluating a packet against the ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfDecision {
    Pass,
    Block,
    Redirect(SocketAddrV4),
    /// Packet should be passed but was logged. The `usize` is the
    /// log entry index.
    Logged(usize),
    /// Routed to deception network.
    Deception,
}

/// Entry recorded when a Log action fires.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub rule_index: usize,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub proto: Proto,
    pub domain: DomainId,
}

/// The PF interposer -- owns the ordered rule list and deception table.
pub struct PfInterposer {
    rules: Vec<PfRule>,
    /// Default action when no rule matches.
    default_action: Action,
    /// Domains currently in deception mode.
    deception_domains: Vec<DomainId>,
    /// Log buffer (ring -- oldest entries evicted when full).
    log: VecDeque<LogEntry>,
    log_max: usize,
}

impl PfInterposer {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: Action::Block, // default-deny
            log: VecDeque::new(),
            log_max: 1024,
            deception_domains: Vec::new(),
        }
    }

    /// Set the default policy (used when no rule matches).
    pub fn set_default(&mut self, action: Action) {
        self.default_action = action;
    }

    /// Append a rule (evaluated last; first-match wins).
    pub fn add_rule(&mut self, rule: PfRule) {
        self.rules.push(rule);
    }

    /// Insert a rule at a specific position.
    pub fn insert_rule(&mut self, index: usize, rule: PfRule) {
        let idx = index.min(self.rules.len());
        self.rules.insert(idx, rule);
    }

    /// Remove all rules.
    pub fn flush(&mut self) {
        self.rules.clear();
    }

    /// Number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Mark a domain for deception routing.
    pub fn enable_deception(&mut self, domain: DomainId) {
        if !self.deception_domains.contains(&domain) {
            self.deception_domains.push(domain);
        }
    }

    /// Remove a domain from deception mode.
    pub fn disable_deception(&mut self, domain: DomainId) {
        self.deception_domains.retain(|&d| d != domain);
    }

    /// Returns true if the domain is in deception mode.
    pub fn is_deception(&self, domain: DomainId) -> bool {
        self.deception_domains.contains(&domain)
    }

    /// Evaluate a packet against the ruleset.
    ///
    /// If `oracle` is provided, rules with `require_provenance` will
    /// consult it. Domains in deception mode are intercepted before
    /// rule evaluation.
    pub fn evaluate(
        &mut self,
        pkt: &PacketInfo,
        oracle: Option<&dyn ProvenanceOracle>,
    ) -> PfDecision {
        // Deception check first -- overrides all rules.
        if self.is_deception(pkt.domain) {
            return PfDecision::Deception;
        }

        for (idx, rule) in self.rules.iter().enumerate() {
            // Direction.
            if !rule.matches_direction(pkt.direction) {
                continue;
            }
            // Protocol.
            if !rule.matches_proto(pkt.proto) {
                continue;
            }
            // Source / destination.
            if !rule.src.matches(&pkt.src) || !rule.dst.matches(&pkt.dst) {
                continue;
            }
            // Domain filter.
            if let Some(dom) = rule.domain_filter {
                if dom != pkt.domain {
                    continue;
                }
            }
            // Provenance gate.
            if rule.require_provenance {
                if let Some(orc) = oracle {
                    if orc.query(pkt.domain) == ProvenanceVerdict::Untrusted {
                        return PfDecision::Block;
                    }
                } else {
                    // No oracle available -- fail closed.
                    return PfDecision::Block;
                }
            }

            // Rule matched -- apply action.
            return match rule.action {
                Action::Pass => PfDecision::Pass,
                Action::Block => PfDecision::Block,
                Action::Redirect(addr) => PfDecision::Redirect(addr),
                Action::Log => {
                    let entry = LogEntry {
                        rule_index: idx,
                        src: pkt.src,
                        dst: pkt.dst,
                        proto: pkt.proto,
                        domain: pkt.domain,
                    };
                    if self.log.len() >= self.log_max {
                        self.log.pop_front();
                    }
                    self.log.push_back(entry);
                    PfDecision::Logged(self.log.len() - 1)
                }
            };
        }

        // No rule matched -- apply default.
        match self.default_action {
            Action::Pass => PfDecision::Pass,
            Action::Block => PfDecision::Block,
            Action::Redirect(addr) => PfDecision::Redirect(addr),
            Action::Log => PfDecision::Pass, // default-log acts as pass
        }
    }

    /// Read the log buffer (returns front and back slices of the ring).
    pub fn log_entries(&self) -> (&[LogEntry], &[LogEntry]) {
        self.log.as_slices()
    }

    /// Number of log entries.
    pub fn log_len(&self) -> usize {
        self.log.len()
    }

    /// Clear the log buffer.
    pub fn clear_log(&mut self) {
        self.log.clear();
    }
}

impl Default for PfInterposer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AllTrusted;
    impl ProvenanceOracle for AllTrusted {
        fn query(&self, _domain: DomainId) -> ProvenanceVerdict {
            ProvenanceVerdict::Trusted
        }
    }

    struct NeverTrusted;
    impl ProvenanceOracle for NeverTrusted {
        fn query(&self, _domain: DomainId) -> ProvenanceVerdict {
            ProvenanceVerdict::Untrusted
        }
    }

    fn pkt(proto: Proto, src_port: u16, dst_ip: [u8; 4], dst_port: u16, domain: DomainId) -> PacketInfo {
        PacketInfo {
            direction: Direction::Out,
            proto,
            src: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), src_port),
            dst: SocketAddrV4::new(Ipv4Addr::new(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]), dst_port),
            domain,
        }
    }

    #[test]
    fn default_deny() {
        let mut pf = PfInterposer::new();
        let p = pkt(Proto::Tcp, 1234, [10, 0, 0, 2], 80, 1);
        assert_eq!(pf.evaluate(&p, None), PfDecision::Block);
    }

    #[test]
    fn explicit_pass() {
        let mut pf = PfInterposer::new();
        pf.add_rule(PfRule::pass_all());
        let p = pkt(Proto::Tcp, 1234, [10, 0, 0, 2], 80, 1);
        assert_eq!(pf.evaluate(&p, None), PfDecision::Pass);
    }

    #[test]
    fn first_match_wins() {
        let mut pf = PfInterposer::new();
        // Block TCP to port 22.
        pf.add_rule(PfRule {
            direction: Direction::Both,
            proto: Proto::Tcp,
            src: AddrMatch::ANY,
            dst: AddrMatch::new(None, Some(22)),
            action: Action::Block,
            domain_filter: None,
            require_provenance: false,
        });
        // Pass everything else.
        pf.add_rule(PfRule::pass_all());

        let ssh = pkt(Proto::Tcp, 5000, [10, 0, 0, 2], 22, 1);
        assert_eq!(pf.evaluate(&ssh, None), PfDecision::Block);

        let http = pkt(Proto::Tcp, 5000, [10, 0, 0, 2], 80, 1);
        assert_eq!(pf.evaluate(&http, None), PfDecision::Pass);
    }

    #[test]
    fn redirect_action() {
        let mut pf = PfInterposer::new();
        let redir_target = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 8080);
        pf.add_rule(PfRule {
            direction: Direction::Out,
            proto: Proto::Tcp,
            src: AddrMatch::ANY,
            dst: AddrMatch::new(None, Some(80)),
            action: Action::Redirect(redir_target),
            domain_filter: None,
            require_provenance: false,
        });
        let p = pkt(Proto::Tcp, 3000, [10, 0, 0, 2], 80, 1);
        assert_eq!(pf.evaluate(&p, None), PfDecision::Redirect(redir_target));
    }

    #[test]
    fn log_action() {
        let mut pf = PfInterposer::new();
        pf.add_rule(PfRule {
            direction: Direction::Both,
            proto: Proto::Any,
            src: AddrMatch::ANY,
            dst: AddrMatch::ANY,
            action: Action::Log,
            domain_filter: None,
            require_provenance: false,
        });
        let p = pkt(Proto::Udp, 53, [8, 8, 8, 8], 53, 1);
        let decision = pf.evaluate(&p, None);
        assert!(matches!(decision, PfDecision::Logged(_)));
        assert_eq!(pf.log_len(), 1);
    }

    #[test]
    fn provenance_blocks_untrusted() {
        let mut pf = PfInterposer::new();
        pf.add_rule(PfRule {
            direction: Direction::Both,
            proto: Proto::Any,
            src: AddrMatch::ANY,
            dst: AddrMatch::ANY,
            action: Action::Pass,
            domain_filter: None,
            require_provenance: true,
        });
        let p = pkt(Proto::Tcp, 1234, [10, 0, 0, 2], 443, 1);

        // Untrusted domain gets blocked.
        assert_eq!(pf.evaluate(&p, Some(&NeverTrusted)), PfDecision::Block);
        // Trusted domain passes.
        assert_eq!(pf.evaluate(&p, Some(&AllTrusted)), PfDecision::Pass);
    }

    #[test]
    fn deception_overrides_rules() {
        let mut pf = PfInterposer::new();
        pf.add_rule(PfRule::pass_all());
        pf.enable_deception(42);

        let p = pkt(Proto::Tcp, 1234, [10, 0, 0, 2], 80, 42);
        assert_eq!(pf.evaluate(&p, None), PfDecision::Deception);

        // Non-deception domain still passes.
        let p2 = pkt(Proto::Tcp, 1234, [10, 0, 0, 2], 80, 1);
        assert_eq!(pf.evaluate(&p2, None), PfDecision::Pass);

        pf.disable_deception(42);
        assert_eq!(pf.evaluate(&p, None), PfDecision::Pass);
    }

    #[test]
    fn domain_filter() {
        let mut pf = PfInterposer::new();
        // Block only domain 99.
        pf.add_rule(PfRule {
            direction: Direction::Both,
            proto: Proto::Any,
            src: AddrMatch::ANY,
            dst: AddrMatch::ANY,
            action: Action::Block,
            domain_filter: Some(99),
            require_provenance: false,
        });
        pf.add_rule(PfRule::pass_all());

        let blocked = pkt(Proto::Tcp, 1234, [10, 0, 0, 2], 80, 99);
        assert_eq!(pf.evaluate(&blocked, None), PfDecision::Block);

        let allowed = pkt(Proto::Tcp, 1234, [10, 0, 0, 2], 80, 1);
        assert_eq!(pf.evaluate(&allowed, None), PfDecision::Pass);
    }
}
