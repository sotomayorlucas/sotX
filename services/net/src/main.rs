//! sotOS Network Service Process
//!
//! Runs as a separate process with its own address space.
//! Drives a virtio-net device and implements the IP/UDP/TCP stack.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};
use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR};
use sotos_pci::PciBus;
use sotos_virtio::net::VirtioNet;

/// Root capability indices (must match kernel write_net_boot_info() order).
const CAP_PCI: usize = 0; // I/O port 0xCF8-0xCFF (PCI config)

/// Default IP configuration — DHCP fallback (QEMU SLIRP defaults).
const DEFAULT_IP: u32 = 0x0A00020F; // 10.0.2.15
const DEFAULT_GATEWAY: u32 = 0x0A000202; // 10.0.2.2
const DEFAULT_SUBNET: u32 = 0xFFFFFF00; // 255.255.255.0

/// Default DNS server — DHCP fallback (QEMU SLIRP default).
const DEFAULT_DNS: u32 = 0x0A000203; // 10.0.2.3

/// 8.8.8.8 — boot connectivity test target.
const PING_TARGET: u32 = 0x08080808;
/// ICMP echo ID for our pings.
const PING_ID: u16 = 0x5054; // "PT" for PingTest

/// UDP echo port.
const UDP_ECHO_PORT: u16 = 5555;
/// TCP echo port.
const TCP_ECHO_PORT: u16 = 7;

// ---- IPC command interface ----
// IPC commands sent via sync endpoints (svc_register "net").
const CMD_PING: u64 = 1;        // arg0 = dst_ip → result = 0 ok / -1 fail
const CMD_DNS_QUERY: u64 = 2;   // arg0 = name_ptr, arg1 = name_len → result = resolved IP
const CMD_TCP_CONNECT: u64 = 3; // arg0 = dst_ip, arg1 = dst_port → result = conn_id
const CMD_TCP_SEND: u64 = 4;    // arg0 = conn_id, arg1 = data_ptr, arg2 = data_len → result = bytes sent
const CMD_TCP_RECV: u64 = 5;    // arg0 = conn_id, arg1 = buf_ptr, arg2 = buf_len → result = bytes read
const CMD_TCP_CLOSE: u64 = 6;   // arg0 = conn_id → result = 0
const CMD_TRACEROUTE_HOP: u64 = 7; // arg0 = dst_ip, arg1 = ttl → result = responder_ip (0=timeout, high bit=reached)

// IPC command queue (atomic, single-slot producer-consumer).
// The IPC handler thread writes cmd + args, then spins on IPC_RESULT.
// The main net loop picks up the command, processes it, writes IPC_RESULT.
static IPC_CMD: AtomicU64 = AtomicU64::new(0);
static IPC_ARG0: AtomicU64 = AtomicU64::new(0);
static IPC_ARG1: AtomicU64 = AtomicU64::new(0);
static IPC_ARG2: AtomicU64 = AtomicU64::new(0);
static IPC_RESULT: AtomicU64 = AtomicU64::new(0);
// Data page for bulk transfers (DNS names, TCP data).
/// Shared data buffer for IPC.
static mut IPC_DATA_BUF: [u8; 4096] = [0; 4096];
/// IPC endpoint cap (set by _start, read by ipc_handler_thread).
static IPC_EP_CAP: AtomicU64 = AtomicU64::new(0);
/// IPC handler stack base.
const IPC_HANDLER_STACK: u64 = 0xD01000;
/// Next ephemeral port for outgoing TCP connections.
static NEXT_EPHEMERAL_PORT: AtomicU64 = AtomicU64::new(49152);

fn print(s: &[u8]) {
    for &b in s { sys::debug_print(b); }
}

fn print_hex_byte(b: u8) {
    let hex = b"0123456789abcdef";
    sys::debug_print(hex[(b >> 4) as usize]);
    sys::debug_print(hex[(b & 0xF) as usize]);
}

fn print_mac(mac: &[u8; 6]) {
    for (i, &b) in mac.iter().enumerate() {
        if i > 0 { sys::debug_print(b':'); }
        print_hex_byte(b);
    }
}

fn print_ip(ip: u32) {
    let bytes = ip.to_be_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 { sys::debug_print(b'.'); }
        print_u32(b as u32);
    }
}

fn print_u32(mut n: u32) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

/// Transmit buffer (shared across the main loop).
static mut TX_FRAME: [u8; 1514] = [0; 1514];
/// IP reply scratch buffer.
static mut IP_BUF: [u8; 1500] = [0; 1500];
/// TCP/UDP reply scratch buffer.
static mut PROTO_BUF: [u8; 1460] = [0; 1460];
/// Protocol state — static to avoid stack overflow (TcpTable is ~9 KiB).
static mut ARP_TABLE: sotos_net::arp::ArpTable = sotos_net::arp::ArpTable::new();
static mut UDP_TABLE: sotos_net::udp::UdpTable = sotos_net::udp::UdpTable::new();
static mut TCP_TABLE: sotos_net::tcp::TcpTable = sotos_net::tcp::TcpTable::new();

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"NET: invalid BootInfo!\n");
        loop { sys::yield_now(); }
    }

    let pci_cap = boot_info.caps[CAP_PCI];
    let pci = PciBus::new(pci_cap);

    // Find virtio-net device (vendor 0x1AF4, device 0x1000).
    let net_dev = match pci.find_device(0x1AF4, 0x1000) {
        Some(d) => d,
        None => {
            print(b"NET: virtio-net device not found\n");
            loop { sys::yield_now(); }
        }
    };

    let mut net = match VirtioNet::init(&net_dev, &pci) {
        Ok(n) => n,
        Err(e) => {
            print(b"NET: init failed: ");
            print(e.as_bytes());
            print(b"\n");
            loop { sys::yield_now(); }
        }
    };

    let mac = net.mac();
    print(b"NET: MAC=");
    print_mac(&mac);
    print(b" IP=");
    print_ip(DEFAULT_IP);
    print(b"\n");

    // Initialize protocol state (statics — too large for stack).
    let arp_table = unsafe { &mut *core::ptr::addr_of_mut!(ARP_TABLE) };
    let udp_table = unsafe { &mut *core::ptr::addr_of_mut!(UDP_TABLE) };
    let tcp_table = unsafe { &mut *core::ptr::addr_of_mut!(TCP_TABLE) };

    // Bind UDP echo socket.
    udp_table.bind(UDP_ECHO_PORT);

    // Listen on TCP echo port.
    tcp_table.listen(TCP_ECHO_PORT);

    print(b"NET: listening UDP=");
    print_u32(UDP_ECHO_PORT as u32);
    print(b" TCP=");
    print_u32(TCP_ECHO_PORT as u32);
    print(b"\n");

    // Register as "net" service for IPC.
    if let Ok(ep_cap) = sys::endpoint_create() {
        IPC_EP_CAP.store(ep_cap, Ordering::Release);
        let name = b"net";
        if sys::svc_register(name.as_ptr() as u64, name.len() as u64, ep_cap).is_ok() {
            print(b"NET: registered as 'net' service\n");
            // Allocate IPC handler stack (1 page).
            if let Ok(stack_frame) = sys::frame_alloc() {
                if sys::map(IPC_HANDLER_STACK, stack_frame, 2 /* MAP_WRITABLE */).is_ok() {
                    let _ = sys::thread_create(
                        ipc_handler_thread as *const () as u64,
                        IPC_HANDLER_STACK + 0x1000,
                    );
                }
            }
        }
    }

    // Bind UDP ports for DNS and DHCP responses.
    udp_table.bind(53);
    udp_table.bind(68); // DHCP client port

    // IP identification counter.
    let mut ip_id: u16 = 1;

    // Mutable IP configuration (can be updated by DHCP).
    let mut our_ip: u32 = DEFAULT_IP;
    let mut gateway_ip: u32 = DEFAULT_GATEWAY;
    let mut dns_server: u32 = DEFAULT_DNS;

    // --- DHCP: try to obtain IP dynamically ---
    {
        let mut dhcp_buf = [0u8; 576]; // DHCP messages can be up to 576 bytes
        let discover_len = sotos_net::dhcp::build_discover(&mac, &mut dhcp_buf);
        if discover_len > 0 {
            // Wrap in UDP (src 68 → dst 67) then IP (0.0.0.0 → 255.255.255.255) then Ethernet broadcast.
            let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
            // UDP is max 1460 but DHCP fits.
            // Build UDP manually since our IP is 0.0.0.0.
            let udp_len = sotos_net::udp::build(
                proto_buf, 0, 0xFFFFFFFF, // src=0.0.0.0, dst=255.255.255.255
                68, 67, &dhcp_buf[..discover_len],
            );
            if udp_len > 0 {
                let ip_buf = unsafe { &mut *core::ptr::addr_of_mut!(IP_BUF) };
                let ip_len = sotos_net::ip::build(
                    ip_buf, 0, 0xFFFFFFFF,
                    sotos_net::ip::PROTO_UDP, next_ip_id(&mut ip_id),
                    &proto_buf[..udp_len],
                );
                if ip_len > 0 {
                    let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
                    let tx_len = sotos_net::eth::build(
                        tx, &sotos_net::eth::BROADCAST_MAC, &mac,
                        sotos_net::eth::ETHERTYPE_IPV4, &ip_buf[..ip_len],
                    );
                    if tx_len > 0 {
                        let _ = net.transmit(&tx[..tx_len]);
                        print(b"NET: DHCP Discover sent\n");
                    }
                }
            }

            // Wait for DHCP Offer (poll up to ~100 iterations).
            let mut dhcp_offer: Option<sotos_net::dhcp::DhcpOffer> = None;
            for _ in 0..100 {
                sys::yield_now();
                while let Some((buf_idx, total_len)) = net.poll_rx() {
                    if total_len > 10 {
                        let frame_len = total_len - 10;
                        let frame_ptr = net.rx_buf(buf_idx);
                        let rx_frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };
                        if let Some((_eh, ep)) = sotos_net::eth::parse(rx_frame) {
                            if let Some((ip_hdr, ip_payload)) = sotos_net::ip::parse(ep) {
                                if ip_hdr.protocol == sotos_net::ip::PROTO_UDP {
                                    if let Some((udp_hdr, udp_payload)) = sotos_net::udp::parse(ip_payload) {
                                        if udp_hdr.dst_port == 68 {
                                            if let Some((msg_type, offer)) = sotos_net::dhcp::parse_response(udp_payload) {
                                                if msg_type == 2 { // DHCP_OFFER
                                                    print(b"NET: DHCP Offer: IP=");
                                                    print_ip(offer.your_ip);
                                                    print(b" GW=");
                                                    print_ip(offer.gateway);
                                                    print(b"\n");
                                                    dhcp_offer = Some(offer);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    net.rx_done(buf_idx);
                    if dhcp_offer.is_some() { break; }
                }
                if dhcp_offer.is_some() { break; }
            }

            // If we got an offer, send DHCP Request.
            if let Some(offer) = dhcp_offer {
                let req_len = sotos_net::dhcp::build_request(&offer, &mac, &mut dhcp_buf);
                if req_len > 0 {
                    let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                    let udp_len = sotos_net::udp::build(
                        proto_buf, 0, 0xFFFFFFFF, 68, 67, &dhcp_buf[..req_len],
                    );
                    if udp_len > 0 {
                        let ip_buf = unsafe { &mut *core::ptr::addr_of_mut!(IP_BUF) };
                        let ip_len = sotos_net::ip::build(
                            ip_buf, 0, 0xFFFFFFFF,
                            sotos_net::ip::PROTO_UDP, next_ip_id(&mut ip_id),
                            &proto_buf[..udp_len],
                        );
                        if ip_len > 0 {
                            let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
                            let tx_len = sotos_net::eth::build(
                                tx, &sotos_net::eth::BROADCAST_MAC, &mac,
                                sotos_net::eth::ETHERTYPE_IPV4, &ip_buf[..ip_len],
                            );
                            if tx_len > 0 {
                                let _ = net.transmit(&tx[..tx_len]);
                                print(b"NET: DHCP Request sent\n");
                            }
                        }
                    }

                    // Wait for DHCP ACK.
                    for _ in 0..100 {
                        sys::yield_now();
                        while let Some((buf_idx, total_len)) = net.poll_rx() {
                            if total_len > 10 {
                                let frame_len = total_len - 10;
                                let frame_ptr = net.rx_buf(buf_idx);
                                let rx_frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };
                                if let Some((_eh, ep)) = sotos_net::eth::parse(rx_frame) {
                                    if let Some((ip_hdr, ip_payload)) = sotos_net::ip::parse(ep) {
                                        if ip_hdr.protocol == sotos_net::ip::PROTO_UDP {
                                            if let Some((udp_hdr, udp_payload)) = sotos_net::udp::parse(ip_payload) {
                                                if udp_hdr.dst_port == 68 {
                                                    if let Some((msg_type, ack)) = sotos_net::dhcp::parse_response(udp_payload) {
                                                        if msg_type == 5 { // DHCP_ACK
                                                            our_ip = ack.your_ip;
                                                            if ack.gateway != 0 {
                                                                gateway_ip = ack.gateway;
                                                            }
                                                            if ack.dns != 0 {
                                                                dns_server = ack.dns;
                                                            }
                                                            print(b"NET: DHCP ACK: IP=");
                                                            print_ip(our_ip);
                                                            print(b" GW=");
                                                            print_ip(gateway_ip);
                                                            print(b"\n");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            net.rx_done(buf_idx);
                        }
                    }
                }
            } else {
                print(b"NET: DHCP timeout, using default IP config\n");
            }
        }
    }

    // --- Ping Google! ---
    // Step 1: ARP for gateway so we know where to send packets.
    let arp_req = sotos_net::arp::build_request(&mac, our_ip, gateway_ip);
    let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
    let tx_len = sotos_net::eth::build(
        tx, &sotos_net::eth::BROADCAST_MAC, &mac,
        sotos_net::eth::ETHERTYPE_ARP, &arp_req,
    );
    if tx_len > 0 {
        let _ = net.transmit(&tx[..tx_len]);
    }
    print(b"NET: ARP request for gateway\n");

    let mut ping_sent = false;
    let mut ping_replied = false;
    let ping_seq: u16 = 1;

    // Main poll loop.
    // We poll RX FIRST (before wait_irq) because transmit()'s wait_tx_completion
    // may consume the IRQ notification while an RX packet is already in the ring.
    loop {
        // Drain all pending RX packets (may have arrived during a previous transmit).
        while let Some((buf_idx, total_len)) = net.poll_rx() {
            if total_len <= 10 {
                net.rx_done(buf_idx);
                continue;
            }

            let frame_len = total_len - 10;
            let frame_ptr = net.rx_buf(buf_idx);
            let frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };

            if let Some((eth_hdr, eth_payload)) = sotos_net::eth::parse(frame) {
                match eth_hdr.ethertype {
                    sotos_net::eth::ETHERTYPE_ARP => {
                        handle_arp(&mut net, arp_table, &mac, eth_payload, &mut ip_id);
                    }
                    sotos_net::eth::ETHERTYPE_IPV4 => {
                        // Check for startup ping reply before passing to handle_ip.
                        if ping_sent && !ping_replied {
                            if let Some((ip_hdr, ip_payload)) = sotos_net::ip::parse(eth_payload) {
                                if ip_hdr.protocol == sotos_net::ip::PROTO_ICMP {
                                    if let Some((id, seq)) = sotos_net::icmp::is_echo_reply(ip_payload) {
                                        if id == PING_ID && seq == ping_seq {
                                            ping_replied = true;
                                            print(b"NET: PONG from ");
                                            print_ip(ip_hdr.src);
                                            print(b" seq=");
                                            print_u32(seq as u32);
                                            print(b" -- google is alive!\n");
                                        }
                                    }
                                }
                            }
                        }
                        handle_ip(
                            &mut net, arp_table, udp_table, tcp_table,
                            &mac, eth_payload, &mut ip_id,
                        );
                    }
                    _ => {}
                }
            }

            net.rx_done(buf_idx);
        }

        // Check for TCP connections with data to echo back.
        for i in 0..16 {
            if tcp_table.conns[i].active
                && tcp_table.conns[i].state == sotos_net::tcp::TcpState::Established
                && tcp_table.conns[i].recv_len > 0
            {
                let mut echo_data = [0u8; 2048];
                let n = tcp_table.read(i, &mut echo_data);
                if n > 0 {
                    let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                    if let Some(seg_len) = tcp_table.send(i, DEFAULT_IP, &echo_data[..n], proto_buf) {
                        let ip_buf = unsafe { &mut *core::ptr::addr_of_mut!(IP_BUF) };
                        let ip_len = sotos_net::ip::build(
                            ip_buf, DEFAULT_IP, tcp_table.conns[i].remote_ip,
                            sotos_net::ip::PROTO_TCP, next_ip_id(&mut ip_id),
                            &proto_buf[..seg_len],
                        );
                        if ip_len > 0 {
                            let dst_mac = arp_table.lookup(tcp_table.conns[i].remote_ip)
                                .or_else(|| arp_table.lookup(DEFAULT_GATEWAY))
                                .unwrap_or(sotos_net::eth::BROADCAST_MAC);
                            let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
                            let tx_len = sotos_net::eth::build(
                                tx, &dst_mac, &mac,
                                sotos_net::eth::ETHERTYPE_IPV4, &ip_buf[..ip_len],
                            );
                            if tx_len > 0 {
                                let _ = net.transmit(&tx[..tx_len]);
                            }
                        }
                    }
                }
            }
        }

        // --- Ping Google: send once we have gateway MAC ---
        if !ping_sent {
            if let Some(gw_mac) = arp_table.lookup(gateway_ip) {
                print(b"NET: gateway MAC=");
                print_mac(&gw_mac);
                print(b"\n");

                let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                let icmp_len = sotos_net::icmp::build_echo_request(proto_buf, PING_ID, ping_seq);
                if icmp_len > 0 {
                    let ip_buf = unsafe { &mut *core::ptr::addr_of_mut!(IP_BUF) };
                    let ip_len = sotos_net::ip::build(
                        ip_buf, DEFAULT_IP, PING_TARGET,
                        sotos_net::ip::PROTO_ICMP, next_ip_id(&mut ip_id),
                        &proto_buf[..icmp_len],
                    );
                    if ip_len > 0 {
                        let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
                        let tx_len = sotos_net::eth::build(
                            tx, &gw_mac, &mac,
                            sotos_net::eth::ETHERTYPE_IPV4, &ip_buf[..ip_len],
                        );
                        if tx_len > 0 {
                            let _ = net.transmit(&tx[..tx_len]);
                            print(b"NET: PING ");
                            print_ip(PING_TARGET);
                            print(b" seq=");
                            print_u32(ping_seq as u32);
                            print(b"\n");
                            ping_sent = true;
                            // Loop back to poll RX — the echo reply may already
                            // be in the ring (IRQ consumed by wait_tx_completion).
                            continue;
                        }
                    }
                }
            }
        }

        // Process IPC commands (non-blocking check).
        let cmd = IPC_CMD.load(Ordering::Acquire);
        if cmd != 0 {
            let arg0 = IPC_ARG0.load(Ordering::Acquire);
            let arg1 = IPC_ARG1.load(Ordering::Acquire);
            let arg2 = IPC_ARG2.load(Ordering::Acquire);
            let result = match cmd {
                CMD_PING => {
                    // Send ICMP echo request to arg0 (IP address), arg1 = seq number.
                    let dst_ip = arg0 as u32;
                    let ping_seq = arg1 as u16;
                    let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                    let icmp_len = sotos_net::icmp::build_echo_request(proto_buf, PING_ID, ping_seq);
                    if icmp_len > 0 {
                        send_ip_reply(&mut net, arp_table, &mac, dst_ip,
                            sotos_net::ip::PROTO_ICMP, &mut ip_id, &proto_buf[..icmp_len]);
                        // Wait for ICMP echo reply (poll up to ~600 iterations).
                        let mut got_reply: u64 = 0;
                        for _ in 0..600 {
                            sys::yield_now();
                            while let Some((buf_idx, total_len)) = net.poll_rx() {
                                if total_len > 10 {
                                    let frame_len = total_len - 10;
                                    let frame_ptr = net.rx_buf(buf_idx);
                                    let rx_frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };
                                    if let Some((_eh, ep)) = sotos_net::eth::parse(rx_frame) {
                                        if let Some((ip_hdr, ip_payload)) = sotos_net::ip::parse(ep) {
                                            if ip_hdr.protocol == sotos_net::ip::PROTO_ICMP {
                                                if let Some((reply_id, reply_seq)) = sotos_net::icmp::is_echo_reply(ip_payload) {
                                                    if reply_id == PING_ID && reply_seq == ping_seq {
                                                        // Return TTL in upper 32 bits, 1 in lower.
                                                        got_reply = 1 | ((ip_hdr.ttl as u64) << 32);
                                                    }
                                                }
                                            } else {
                                                handle_ip(&mut net, arp_table, udp_table, tcp_table, &mac, ep, &mut ip_id);
                                            }
                                        }
                                    }
                                }
                                net.rx_done(buf_idx);
                                if got_reply != 0 { break; }
                            }
                            if got_reply != 0 { break; }
                        }
                        got_reply
                    } else {
                        0u64
                    }
                }
                CMD_DNS_QUERY => {
                    // DNS query: name is in IPC_DATA_BUF[..arg1]
                    let name_len = arg1 as usize;
                    let name = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(IPC_DATA_BUF) as *const u8, name_len) };
                    let mut query_buf = [0u8; 512];
                    let qlen = sotos_net::dns::build_query(name, &mut query_buf);
                    if qlen > 0 {
                        // Send DNS query via UDP to dns_server:53
                        let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                        let udp_len = sotos_net::udp::build(
                            proto_buf, DEFAULT_IP, dns_server,
                            53, 53, &query_buf[..qlen],
                        );
                        if udp_len > 0 {
                            send_ip_reply(&mut net, arp_table, &mac, dns_server,
                                sotos_net::ip::PROTO_UDP, &mut ip_id, &proto_buf[..udp_len]);
                        }
                        // Wait for DNS response (poll up to ~200 iterations).
                        let mut resolved: u64 = 0;
                        for _ in 0..200 {
                            sys::yield_now();
                            while let Some((buf_idx, total_len)) = net.poll_rx() {
                                if total_len > 10 {
                                    let frame_len = total_len - 10;
                                    let frame_ptr = net.rx_buf(buf_idx);
                                    let rx_frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };
                                    if let Some((eth_hdr, eth_payload)) = sotos_net::eth::parse(rx_frame) {
                                        match eth_hdr.ethertype {
                                            sotos_net::eth::ETHERTYPE_ARP => {
                                                handle_arp(&mut net, arp_table, &mac, eth_payload, &mut ip_id);
                                            }
                                            sotos_net::eth::ETHERTYPE_IPV4 => {
                                                if let Some((ip_hdr, ip_payload)) = sotos_net::ip::parse(eth_payload) {
                                                    if ip_hdr.protocol == sotos_net::ip::PROTO_UDP {
                                                        if let Some((udp_hdr, udp_payload)) = sotos_net::udp::parse(ip_payload) {
                                                            if udp_hdr.src_port == 53 {
                                                                if let Some(ip) = sotos_net::dns::parse_response(udp_payload) {
                                                                    resolved = ip as u64;
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        // Handle other protocols normally.
                                                        handle_ip(&mut net, arp_table, udp_table, tcp_table, &mac, eth_payload, &mut ip_id);
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                net.rx_done(buf_idx);
                                if resolved != 0 { break; }
                            }
                            if resolved != 0 { break; }
                        }
                        resolved
                    } else {
                        0 // failed to build query
                    }
                }
                CMD_TCP_CONNECT => {
                    // Active TCP open: arg0 = dst_ip, arg1 = dst_port
                    let dst_ip = arg0 as u32;
                    let dst_port = arg1 as u16;
                    let local_port = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed) as u16;
                    let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                    match tcp_table.connect(local_port, dst_ip, dst_port, DEFAULT_IP, proto_buf) {
                        Some((conn_id, seg_len)) => {
                            send_ip_reply(&mut net, arp_table, &mac, dst_ip,
                                sotos_net::ip::PROTO_TCP, &mut ip_id, &proto_buf[..seg_len]);
                            // Wait for SYN+ACK (poll up to ~500 iterations).
                            for _ in 0..500 {
                                sys::yield_now();
                                while let Some((buf_idx, total_len)) = net.poll_rx() {
                                    if total_len > 10 {
                                        let frame_len = total_len - 10;
                                        let frame_ptr = net.rx_buf(buf_idx);
                                        let rx_frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };
                                        if let Some((_eh, ep)) = sotos_net::eth::parse(rx_frame) {
                                            handle_ip(&mut net, arp_table, udp_table, tcp_table, &mac, ep, &mut ip_id);
                                        }
                                    }
                                    net.rx_done(buf_idx);
                                }
                                let st = tcp_table.conns[conn_id].state;
                                if st == sotos_net::tcp::TcpState::Established
                                    || st == sotos_net::tcp::TcpState::Closed {
                                    break;
                                }
                            }
                            if tcp_table.conns[conn_id].state == sotos_net::tcp::TcpState::Established {
                                conn_id as u64
                            } else {
                                // Connection failed — clean up the slot so it doesn't leak.
                                tcp_table.conns[conn_id].active = false;
                                tcp_table.conns[conn_id].state = sotos_net::tcp::TcpState::Closed;
                                (-1i64) as u64
                            }
                        }
                        None => (-1i64) as u64,
                    }
                }
                CMD_TCP_SEND => {
                    // arg0 = conn_id, arg1 = data in IPC_DATA_BUF, arg2 = data_len
                    let conn_id = arg0 as usize;
                    if conn_id >= 16 { (-1i64) as u64 } else {
                    let data_len = arg2 as usize;
                    let data = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(IPC_DATA_BUF) as *const u8, data_len.min(4096)) };
                    let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                    if let Some(seg_len) = tcp_table.send(conn_id, DEFAULT_IP, data, proto_buf) {
                        let dst_ip = tcp_table.conns[conn_id].remote_ip;
                        send_ip_reply(&mut net, arp_table, &mac, dst_ip,
                            sotos_net::ip::PROTO_TCP, &mut ip_id, &proto_buf[..seg_len]);
                        data_len as u64
                    } else {
                        (-1i64) as u64
                    }
                    }
                }
                CMD_TCP_RECV => {
                    // arg0 = conn_id, arg1 = max_len
                    let conn_id = arg0 as usize;
                    if conn_id >= 16 { 0u64 } else {
                    let max_len = (arg1 as usize).min(4096);
                    // Poll for incoming data (up to ~300 iterations).
                    for _ in 0..300 {
                        if tcp_table.conns[conn_id].recv_len > 0 { break; }
                        if !tcp_table.conns[conn_id].active { break; }
                        sys::yield_now();
                        while let Some((buf_idx, total_len)) = net.poll_rx() {
                            if total_len > 10 {
                                let frame_len = total_len - 10;
                                let frame_ptr = net.rx_buf(buf_idx);
                                let rx_frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };
                                if let Some((_eh, ep)) = sotos_net::eth::parse(rx_frame) {
                                    handle_ip(&mut net, arp_table, udp_table, tcp_table, &mac, ep, &mut ip_id);
                                }
                            }
                            net.rx_done(buf_idx);
                        }
                    }
                    let mut read_buf = [0u8; 2048];
                    let n = tcp_table.read(conn_id, &mut read_buf[..max_len.min(2048)]);
                    if n > 0 {
                        unsafe {
                            let ipc_dst = core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8, n);
                            ipc_dst.copy_from_slice(&read_buf[..n]);
                        }
                    }
                    n as u64
                    }
                }
                CMD_TCP_CLOSE => {
                    let conn_id = arg0 as usize;
                    if conn_id >= 16 { 0u64 } else {
                    let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                    if let Some(seg_len) = tcp_table.close(conn_id, DEFAULT_IP, proto_buf) {
                        let dst_ip = tcp_table.conns[conn_id].remote_ip;
                        send_ip_reply(&mut net, arp_table, &mac, dst_ip,
                            sotos_net::ip::PROTO_TCP, &mut ip_id, &proto_buf[..seg_len]);
                    }
                    0u64
                    }
                }
                CMD_TRACEROUTE_HOP => {
                    // Send ICMP echo with specific TTL, wait for Time Exceeded or Echo Reply.
                    // arg0 = dst_ip, arg1 = ttl
                    let dst_ip = arg0 as u32;
                    let ttl = arg1 as u8;
                    let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                    let icmp_len = sotos_net::icmp::build_echo_request(proto_buf, PING_ID, ttl as u16);
                    if icmp_len > 0 {
                        // Build IP with custom TTL.
                        let ip_buf = unsafe { &mut *core::ptr::addr_of_mut!(IP_BUF) };
                        let ip_len = sotos_net::ip::build_with_ttl(
                            ip_buf, DEFAULT_IP, dst_ip,
                            sotos_net::ip::PROTO_ICMP, next_ip_id(&mut ip_id),
                            ttl, &proto_buf[..icmp_len],
                        );
                        if ip_len > 0 {
                            let next_hop = if (dst_ip & DEFAULT_SUBNET) == (DEFAULT_IP & DEFAULT_SUBNET) {
                                dst_ip
                            } else {
                                gateway_ip
                            };
                            let dst_mac = arp_table.lookup(next_hop).unwrap_or(sotos_net::eth::BROADCAST_MAC);
                            let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
                            let tx_len = sotos_net::eth::build(
                                tx, &dst_mac, &mac,
                                sotos_net::eth::ETHERTYPE_IPV4, &ip_buf[..ip_len],
                            );
                            if tx_len > 0 {
                                let _ = net.transmit(&tx[..tx_len]);
                            }
                        }
                        // Wait for ICMP response (Time Exceeded or Echo Reply).
                        let mut result_ip: u64 = 0;
                        for _ in 0..200 {
                            sys::yield_now();
                            while let Some((buf_idx, total_len)) = net.poll_rx() {
                                if total_len > 10 {
                                    let frame_len = total_len - 10;
                                    let frame_ptr = net.rx_buf(buf_idx);
                                    let rx_frame = unsafe { core::slice::from_raw_parts(frame_ptr, frame_len) };
                                    if let Some((_eh, ep)) = sotos_net::eth::parse(rx_frame) {
                                        if let Some((ip_hdr, ip_payload)) = sotos_net::ip::parse(ep) {
                                            if ip_hdr.protocol == sotos_net::ip::PROTO_ICMP {
                                                if sotos_net::icmp::is_time_exceeded(ip_payload) {
                                                    // TTL expired — hop router responded.
                                                    result_ip = ip_hdr.src as u64;
                                                } else if sotos_net::icmp::is_echo_reply(ip_payload).is_some() {
                                                    // Reached destination.
                                                    result_ip = ip_hdr.src as u64 | (1u64 << 32);
                                                }
                                            } else {
                                                handle_ip(&mut net, arp_table, udp_table, tcp_table, &mac, ep, &mut ip_id);
                                            }
                                        }
                                    }
                                }
                                net.rx_done(buf_idx);
                                if result_ip != 0 { break; }
                            }
                            if result_ip != 0 { break; }
                        }
                        result_ip
                    } else {
                        0u64
                    }
                }
                _ => (-1i64) as u64,
            };
            IPC_RESULT.store(result, Ordering::Release);
            IPC_CMD.store(0, Ordering::Release); // Signal completion.
        }

        // Yield and poll — don't use blocking wait_irq() so we can also
        // pick up IPC commands from the handler thread.
        sys::yield_now();
        net.ack_irq();
    }
}

/// IPC handler thread — blocks on recv(), writes command to atomic queue,
/// waits for main loop to process, then replies.
#[unsafe(no_mangle)]
pub extern "C" fn ipc_handler_thread() -> ! {
    let ep_cap = IPC_EP_CAP.load(Ordering::Acquire);
    print(b"NET: IPC handler thread started\n");

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let cmd = msg.tag;
        let arg0 = msg.regs[0];
        let arg1 = msg.regs[1];
        let arg2 = msg.regs[2];

        // For commands that pass data, copy from caller's regs into IPC_DATA_BUF.
        // (The caller writes data pointer + len; we need to read from the shared
        //  address space. Since we're in the same AS as the net main loop, we
        //  can just copy the data if it's in our address space.)
        // For DNS_QUERY: arg0 = name_ptr (in caller's AS!), arg1 = name_len.
        // Problem: caller is in a different AS. We need the data in IPC_DATA_BUF.
        // Solution: caller writes data into IPC_DATA_BUF before calling.
        // Actually, the IPC message regs can carry small data inline.
        // For DNS: name fits in 8 regs * 8 bytes = 64 bytes (enough for hostnames).
        if cmd == CMD_DNS_QUERY {
            // Name is packed in regs[2..] (up to 48 bytes).
            let name_len = arg1 as usize;
            let avail = name_len.min(48);
            unsafe {
                let src = &msg.regs[2] as *const u64 as *const u8;
                core::ptr::copy_nonoverlapping(src, core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8, avail);
            }
        } else if cmd == CMD_TCP_SEND {
            // Data packed in regs[3..] (up to 40 bytes inline).
            let data_len = arg2 as usize;
            let avail = data_len.min(40);
            unsafe {
                let src = &msg.regs[3] as *const u64 as *const u8;
                core::ptr::copy_nonoverlapping(src, core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8, avail);
            }
        }

        // Post command to main loop.
        IPC_ARG0.store(arg0, Ordering::Release);
        IPC_ARG1.store(arg1, Ordering::Release);
        IPC_ARG2.store(arg2, Ordering::Release);
        IPC_RESULT.store(0, Ordering::Release);
        IPC_CMD.store(cmd, Ordering::Release);

        // Wait for main loop to process (IPC_CMD becomes 0).
        loop {
            if IPC_CMD.load(Ordering::Acquire) == 0 {
                break;
            }
            sys::yield_now();
        }

        let result = IPC_RESULT.load(Ordering::Acquire);

        // Build reply.
        let mut reply = IpcMsg::empty();
        reply.regs[0] = result;

        // For TCP_RECV, copy data back into reply regs.
        if cmd == CMD_TCP_RECV && result > 0 {
            let n = (result as usize).min(56); // 7 regs * 8 bytes
            unsafe {
                let dst = &mut reply.regs[1] as *mut u64 as *mut u8;
                core::ptr::copy_nonoverlapping(core::ptr::addr_of!(IPC_DATA_BUF) as *const u8, dst, n);
            }
        }

        let _ = sys::send(ep_cap, &reply);
    }
}

fn next_ip_id(id: &mut u16) -> u16 {
    let v = *id;
    *id = id.wrapping_add(1);
    v
}

fn handle_arp(
    net: &mut VirtioNet,
    arp_table: &mut sotos_net::arp::ArpTable,
    our_mac: &[u8; 6],
    data: &[u8],
    _ip_id: &mut u16,
) {
    if let Some(pkt) = sotos_net::arp::parse(data) {
        if let Some(reply_arp) = sotos_net::arp::handle(arp_table, &pkt, DEFAULT_IP, our_mac) {
            let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
            let tx_len = sotos_net::eth::build(
                tx, &pkt.sender_mac, our_mac,
                sotos_net::eth::ETHERTYPE_ARP, &reply_arp,
            );
            if tx_len > 0 {
                let _ = net.transmit(&tx[..tx_len]);
            }
        }
    }
}

fn handle_ip(
    net: &mut VirtioNet,
    arp_table: &mut sotos_net::arp::ArpTable,
    udp_table: &mut sotos_net::udp::UdpTable,
    tcp_table: &mut sotos_net::tcp::TcpTable,
    our_mac: &[u8; 6],
    data: &[u8],
    ip_id: &mut u16,
) {
    let (ip_hdr, ip_payload) = match sotos_net::ip::parse(data) {
        Some(x) => x,
        None => return,
    };

    // Only process packets addressed to us.
    if ip_hdr.dst != DEFAULT_IP {
        return;
    }

    match ip_hdr.protocol {
        sotos_net::ip::PROTO_ICMP => {
            // Echo replies are handled inline by CMD_PING / CMD_TRACEROUTE_HOP.
            // Handle inbound ICMP: echo requests (ping) and echo replies.
            if sotos_net::icmp::is_echo_reply(ip_payload).is_none() {
                let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                if let Some(icmp_len) = sotos_net::icmp::handle(ip_payload, proto_buf) {
                    send_ip_reply(net, arp_table, our_mac, ip_hdr.src,
                        sotos_net::ip::PROTO_ICMP, ip_id, &proto_buf[..icmp_len]);
                }
            }
        }
        sotos_net::ip::PROTO_UDP => {
            if let Some((udp_hdr, udp_payload)) = sotos_net::udp::parse(ip_payload) {
                if udp_table.is_bound(udp_hdr.dst_port) {
                    // Echo the UDP payload back.
                    let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
                    let udp_len = sotos_net::udp::build(
                        proto_buf, DEFAULT_IP, ip_hdr.src,
                        udp_hdr.dst_port, udp_hdr.src_port,
                        udp_payload,
                    );
                    if udp_len > 0 {
                        send_ip_reply(net, arp_table, our_mac, ip_hdr.src,
                            sotos_net::ip::PROTO_UDP, ip_id, &proto_buf[..udp_len]);
                    }
                }
            }
        }
        sotos_net::ip::PROTO_TCP => {
            let proto_buf = unsafe { &mut *core::ptr::addr_of_mut!(PROTO_BUF) };
            if let Some(seg_len) = tcp_table.handle_segment(
                ip_hdr.src, DEFAULT_IP, ip_payload, proto_buf,
            ) {
                send_ip_reply(net, arp_table, our_mac, ip_hdr.src,
                    sotos_net::ip::PROTO_TCP, ip_id, &proto_buf[..seg_len]);
            }
        }
        _ => {}
    }
}

fn send_ip_reply(
    net: &mut VirtioNet,
    arp_table: &sotos_net::arp::ArpTable,
    our_mac: &[u8; 6],
    dst_ip: u32,
    protocol: u8,
    ip_id: &mut u16,
    transport_data: &[u8],
) {
    let ip_buf = unsafe { &mut *core::ptr::addr_of_mut!(IP_BUF) };
    let ip_len = sotos_net::ip::build(
        ip_buf, DEFAULT_IP, dst_ip, protocol, next_ip_id(ip_id), transport_data,
    );
    if ip_len == 0 { return; }

    // Resolve destination MAC: if on our subnet use direct, else gateway.
    let next_hop = if (dst_ip & DEFAULT_SUBNET) == (DEFAULT_IP & DEFAULT_SUBNET) {
        dst_ip
    } else {
        DEFAULT_GATEWAY
    };
    let dst_mac = arp_table.lookup(next_hop).unwrap_or(sotos_net::eth::BROADCAST_MAC);

    let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
    let tx_len = sotos_net::eth::build(
        tx, &dst_mac, our_mac,
        sotos_net::eth::ETHERTYPE_IPV4, &ip_buf[..ip_len],
    );
    if tx_len > 0 {
        let _ = net.transmit(&tx[..tx_len]);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"NET PANIC");
    if let Some(loc) = info.location() {
        print(b" at ");
        print(loc.file().as_bytes());
        print(b":");
        print_u32(loc.line());
    }
    print(b"\n");
    loop { sys::yield_now(); }
}
