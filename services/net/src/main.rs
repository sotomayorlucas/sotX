//! sotOS Network Service — powered by smoltcp
//!
//! Replaces the manual TCP/IP stack with smoltcp for production-grade networking.
//! Preserves the IPC command interface and Network Mirroring feature.

#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

extern crate alloc;

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR};
use sotos_pci::PciBus;
use sotos_virtio::net::VirtioNet;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::{dhcpv4, icmp, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint,
    Ipv4Address, Ipv4Cidr,
};

// =============================================================================
// Bump allocator (256 KiB, never frees)
// =============================================================================

const HEAP_SIZE: usize = 512 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
static HEAP_POS: AtomicUsize = AtomicUsize::new(0);

struct BumpAlloc;

unsafe impl core::alloc::GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        loop {
            let pos = HEAP_POS.load(Ordering::Relaxed);
            let aligned = (pos + align - 1) & !(align - 1);
            let new_pos = aligned + size;
            if new_pos > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if HEAP_POS
                .compare_exchange_weak(pos, new_pos, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return unsafe { HEAP.as_mut_ptr().add(aligned) };
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAlloc = BumpAlloc;

// =============================================================================
// Critical section (no-op for single-threaded userspace)
// =============================================================================

struct CsImpl;
critical_section::set_impl!(CsImpl);
unsafe impl critical_section::Impl for CsImpl {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_: critical_section::RawRestoreState) {}
}

// =============================================================================
// Constants
// =============================================================================

const CAP_PCI: usize = 0;

const DEFAULT_IP: u32 = 0x0A00020F; // 10.0.2.15
const DEFAULT_GATEWAY: u32 = 0x0A000202; // 10.0.2.2
const DEFAULT_DNS: u32 = 0x0A000203; // 10.0.2.3
const PING_TARGET: u32 = 0x08080808; // 8.8.8.8
const PING_ID: u16 = 0x5054;

const TCP_ECHO_PORT: u16 = 7;

// IPC command codes (must match LUCAS / child_handler)
const CMD_PING: u64 = 1;
const CMD_DNS_QUERY: u64 = 2;
const CMD_TCP_CONNECT: u64 = 3;
const CMD_TCP_SEND: u64 = 4;
const CMD_TCP_RECV: u64 = 5;
const CMD_TCP_CLOSE: u64 = 6;
const CMD_TRACEROUTE_HOP: u64 = 7;
const CMD_UDP_BIND: u64 = 8;
const CMD_UDP_SENDTO: u64 = 9;
const CMD_UDP_RECV: u64 = 10;
const CMD_TCP_STATUS: u64 = 11;
const CMD_NET_MIRROR: u64 = 12;
const CMD_UDP_HAS_DATA: u64 = 13;

// IPC atomic command queue
static NET_MIRROR: AtomicU64 = AtomicU64::new(0);
static IPC_CMD: AtomicU64 = AtomicU64::new(0);
static IPC_RAW_TAG: AtomicU64 = AtomicU64::new(0);
static IPC_ARG0: AtomicU64 = AtomicU64::new(0);
static IPC_ARG1: AtomicU64 = AtomicU64::new(0);
static IPC_ARG2: AtomicU64 = AtomicU64::new(0);
static IPC_ARG3: AtomicU64 = AtomicU64::new(0);
static IPC_RESULT: AtomicU64 = AtomicU64::new(0);
/// Total bytes of last UDP recv (stored for multi-chunk reads).
static IPC_UDP_RECV_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Total bytes of last TCP recv (stored for multi-chunk reads).
static IPC_TCP_RECV_TOTAL: AtomicU64 = AtomicU64::new(0);
static mut IPC_DATA_BUF: [u8; 4096] = [0; 4096];
static IPC_EP_CAP: AtomicU64 = AtomicU64::new(0);
const IPC_HANDLER_STACK: u64 = 0xD01000;
static NEXT_EPHEMERAL_PORT: AtomicU64 = AtomicU64::new(49152);

// Socket handle tables
const MAX_TCP: usize = 16;
const MAX_UDP: usize = 8;
static mut TCP_SLOTS: [Option<SocketHandle>; MAX_TCP] = [None; MAX_TCP];
static mut UDP_SLOTS: [(Option<SocketHandle>, u16); MAX_UDP] = [(None, 0); MAX_UDP];

// =============================================================================
// Print helpers
// =============================================================================

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_u32(mut n: u32) {
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

fn print_hex_byte(b: u8) {
    let hex = b"0123456789abcdef";
    sys::debug_print(hex[(b >> 4) as usize]);
    sys::debug_print(hex[(b & 0xF) as usize]);
}

fn print_mac(mac: &[u8; 6]) {
    for (i, &b) in mac.iter().enumerate() {
        if i > 0 {
            sys::debug_print(b':');
        }
        print_hex_byte(b);
    }
}

fn print_ip(ip: u32) {
    let bytes = ip.to_be_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            sys::debug_print(b'.');
        }
        print_u32(b as u32);
    }
}

// =============================================================================
// Timestamp (RDTSC at assumed 2 GHz)
// =============================================================================

fn now() -> Instant {
    let tsc: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            "shl rdx, 32",
            "or rax, rdx",
            out("rax") tsc,
            out("rdx") _,
        );
    }
    Instant::from_millis((tsc / 2_000_000) as i64)
}

// =============================================================================
// smoltcp Device implementation for VirtioNet
// =============================================================================

struct VirtioDevice {
    net: VirtioNet,
}

struct VirtioRxToken {
    buf: [u8; 1514],
    len: usize,
}

struct VirtioTxToken<'a> {
    net: &'a mut VirtioNet,
}

impl smoltcp::phy::RxToken for VirtioRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buf[..self.len])
    }
}

impl<'a> smoltcp::phy::TxToken for VirtioTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = [0u8; 1514];
        let result = f(&mut buf[..len]);
        let _ = self.net.transmit(&buf[..len]);
        result
    }
}

impl Device for VirtioDevice {
    type RxToken<'a> = VirtioRxToken where Self: 'a;
    type TxToken<'a> = VirtioTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let (idx, total_len) = self.net.poll_rx()?;
        let frame_len = total_len.saturating_sub(10);
        if frame_len == 0 || frame_len > 1514 {
            self.net.rx_done(idx);
            return None;
        }
        let ptr = self.net.rx_buf(idx);
        let data = unsafe { core::slice::from_raw_parts(ptr, frame_len) };
        let mut buf = [0u8; 1514];
        buf[..frame_len].copy_from_slice(data);
        self.net.rx_done(idx);

        // Network mirroring — log before smoltcp processes
        if NET_MIRROR.load(Ordering::Relaxed) != 0 {
            mirror_frame(&buf[..frame_len]);
        }

        Some((
            VirtioRxToken { buf, len: frame_len },
            VirtioTxToken { net: &mut self.net },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken { net: &mut self.net })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ethernet;
        caps
    }
}

// =============================================================================
// Network mirroring — raw frame inspection
// =============================================================================

fn mirror_frame(frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 => {
            if frame.len() < 34 {
                return;
            }
            let protocol = frame[23];
            let src_ip = u32::from_be_bytes([frame[26], frame[27], frame[28], frame[29]]);
            let dst_ip = u32::from_be_bytes([frame[30], frame[31], frame[32], frame[33]]);
            print(b"[MIRROR] ");
            match protocol {
                6 => print(b"TCP"),
                17 => print(b"UDP"),
                1 => print(b"ICMP"),
                _ => print(b"???"),
            }
            print(b" ");
            print_ip(src_ip);
            print(b" -> ");
            print_ip(dst_ip);
            if (protocol == 6 || protocol == 17) && frame.len() >= 38 {
                let ihl = ((frame[14] & 0xF) as usize) * 4;
                let tp = 14 + ihl;
                if frame.len() >= tp + 4 {
                    let sp = u16::from_be_bytes([frame[tp], frame[tp + 1]]);
                    let dp = u16::from_be_bytes([frame[tp + 2], frame[tp + 3]]);
                    print(b" :");
                    print_u32(sp as u32);
                    print(b"->:");
                    print_u32(dp as u32);
                }
            }
            print(b" len=");
            print_u32(frame.len() as u32);
            print(b"\n");
        }
        0x0806 => {
            print(b"[MIRROR] ARP len=");
            print_u32(frame.len() as u32);
            print(b"\n");
        }
        _ => {}
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn ip_from_u32(ip: u32) -> Ipv4Address {
    Ipv4Address::from_bytes(&ip.to_be_bytes())
}

fn u32_from_ip(ip: &Ipv4Address) -> u32 {
    u32::from_be_bytes(ip.0)
}

fn alloc_tcp_slot() -> Option<usize> {
    let slots = unsafe { &*core::ptr::addr_of!(TCP_SLOTS) };
    for (i, slot) in slots.iter().enumerate() {
        if slot.is_none() {
            return Some(i);
        }
    }
    None
}

fn find_udp_slot(port: u16) -> Option<usize> {
    let slots = unsafe { &*core::ptr::addr_of!(UDP_SLOTS) };
    for (i, (handle, p)) in slots.iter().enumerate() {
        if handle.is_some() && *p == port {
            return Some(i);
        }
    }
    None
}

fn alloc_udp_slot() -> Option<usize> {
    let slots = unsafe { &*core::ptr::addr_of!(UDP_SLOTS) };
    for (i, (handle, _)) in slots.iter().enumerate() {
        if handle.is_none() {
            return Some(i);
        }
    }
    None
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// Minimal DNS query builder (A record)
fn build_dns_query(name: &[u8], buf: &mut [u8]) -> usize {
    if buf.len() < 64 || name.is_empty() {
        return 0;
    }
    buf[0] = 0x12;
    buf[1] = 0x34; // ID
    buf[2] = 0x01;
    buf[3] = 0x00; // Flags: RD=1
    buf[4] = 0x00;
    buf[5] = 0x01; // QDCOUNT=1
    buf[6..12].fill(0);

    let mut pos = 12;
    let mut label_start = pos;
    pos += 1;
    for &b in name {
        if b == b'.' {
            buf[label_start] = (pos - label_start - 1) as u8;
            label_start = pos;
            pos += 1;
        } else {
            if pos >= buf.len() - 5 {
                return 0;
            }
            buf[pos] = b;
            pos += 1;
        }
    }
    buf[label_start] = (pos - label_start - 1) as u8;
    buf[pos] = 0; // root
    pos += 1;
    buf[pos] = 0;
    buf[pos + 1] = 1; // QTYPE=A
    buf[pos + 2] = 0;
    buf[pos + 3] = 1; // QCLASS=IN
    pos + 4
}

fn parse_dns_response(data: &[u8]) -> Option<u32> {
    if data.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    // Skip QNAME
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len >= 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    pos += 4; // QTYPE + QCLASS

    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }
        if data[pos] >= 0xC0 {
            pos += 2;
        } else {
            while pos < data.len() {
                let len = data[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                pos += 1 + len;
            }
        }
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlength == 4 && pos + 4 <= data.len() {
            return Some(u32::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]));
        }
        pos += rdlength;
    }
    None
}

// Build raw ICMP echo request packet (8 bytes: type+code+cksum+id+seq)
fn build_echo_request(id: u16, seq: u16) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 8; // Echo Request
    pkt[4] = (id >> 8) as u8;
    pkt[5] = id as u8;
    pkt[6] = (seq >> 8) as u8;
    pkt[7] = seq as u8;
    let cksum = icmp_checksum(&pkt);
    pkt[2] = (cksum >> 8) as u8;
    pkt[3] = cksum as u8;
    pkt
}

// =============================================================================
// Global network state for embassy async tasks
// =============================================================================

struct NetState {
    device: VirtioDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    dhcp_handle: SocketHandle,
    icmp_handle: SocketHandle,
    echo_handle: SocketHandle,
}

static mut G_NET: MaybeUninit<NetState> = MaybeUninit::uninit();
static mut G_EXECUTOR: MaybeUninit<embassy_executor::Executor> = MaybeUninit::uninit();
static BOOT_PING_PHASE: AtomicU8 = AtomicU8::new(0);

/// Yield to both the OS scheduler and the embassy executor.
async fn async_yield() {
    struct YieldOnce(bool);
    impl core::future::Future for YieldOnce {
        type Output = ();
        fn poll(
            mut self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<()> {
            if self.0 {
                core::task::Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        }
    }
    sys::yield_now();
    YieldOnce(false).await;
}

// =============================================================================
// Main entry point
// =============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"NET: invalid BootInfo!\n");
        loop {
            sys::yield_now();
        }
    }

    let pci_cap = boot_info.caps[CAP_PCI];
    let pci = PciBus::new(pci_cap);

    let net_dev = match pci.find_device(0x1AF4, 0x1000) {
        Some(d) => d,
        None => {
            print(b"NET: virtio-net device not found\n");
            loop {
                sys::yield_now();
            }
        }
    };

    let net = match VirtioNet::init(&net_dev, &pci) {
        Ok(n) => n,
        Err(e) => {
            print(b"NET: init failed: ");
            print(e.as_bytes());
            print(b"\n");
            loop {
                sys::yield_now();
            }
        }
    };

    let mac = net.mac();
    print(b"NET: MAC=");
    print_mac(&mac);
    print(b"\n");

    // Register as "net" service for IPC
    if let Ok(ep_cap) = sys::endpoint_create() {
        IPC_EP_CAP.store(ep_cap, Ordering::Release);
        let name = b"net";
        if sys::svc_register(name.as_ptr() as u64, name.len() as u64, ep_cap).is_ok() {
            print(b"NET: registered as 'net' service\n");
            if let Ok(stack_frame) = sys::frame_alloc() {
                if sys::map(IPC_HANDLER_STACK, stack_frame, 2).is_ok() {
                    let _ = sys::thread_create(
                        ipc_handler_thread as *const () as u64,
                        IPC_HANDLER_STACK + 0x1000,
                    );
                }
            }
        }
    }

    // Wrap VirtioNet in smoltcp Device
    let mut device = VirtioDevice { net };

    // Create smoltcp interface
    let hw_addr = HardwareAddress::Ethernet(EthernetAddress::from_bytes(&mac));
    let mut config = Config::new(hw_addr);
    config.random_seed = now().total_millis() as u64;

    let mut iface = Interface::new(config, &mut device, now());

    // Set default IP (will be updated by DHCP)
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(ip_from_u32(DEFAULT_IP), 24)));
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(ip_from_u32(DEFAULT_GATEWAY))
        .ok();

    // Create socket set
    let mut sockets = SocketSet::new(alloc::vec![]);

    // DHCP client socket
    let dhcp_socket = dhcpv4::Socket::new();
    let dhcp_handle = sockets.add(dhcp_socket);

    // ICMP socket for ping / traceroute (bind to receive all ICMP)
    let icmp_rx = icmp::PacketBuffer::new(
        alloc::vec![icmp::PacketMetadata::EMPTY; 4],
        alloc::vec![0u8; 2048],
    );
    let icmp_tx = icmp::PacketBuffer::new(
        alloc::vec![icmp::PacketMetadata::EMPTY; 4],
        alloc::vec![0u8; 2048],
    );
    let mut icmp_socket = icmp::Socket::new(icmp_rx, icmp_tx);
    let _ = icmp_socket.bind(icmp::Endpoint::Ident(PING_ID));
    let icmp_handle = sockets.add(icmp_socket);

    // TCP echo server (port 7)
    let echo_rx = tcp::SocketBuffer::new(alloc::vec![0u8; 2048]);
    let echo_tx = tcp::SocketBuffer::new(alloc::vec![0u8; 2048]);
    let mut echo_socket = tcp::Socket::new(echo_rx, echo_tx);
    let _ = echo_socket.listen(TCP_ECHO_PORT);
    let echo_handle = sockets.add(echo_socket);

    print(b"NET: smoltcp interface ready, DHCP starting...\n");

    // Store network state in global for async tasks
    unsafe {
        G_NET.write(NetState {
            device,
            iface,
            sockets,
            dhcp_handle,
            icmp_handle,
            echo_handle,
        });

        // Create embassy executor and spawn async tasks
        print(b"NET: starting embassy async executor\n");
        let executor = G_EXECUTOR.write(embassy_executor::Executor::new());
        executor.run(|spawner| {
            spawner.spawn(net_poll_task()).unwrap();
            spawner.spawn(boot_ping_task()).unwrap();
        });
    }
}

// =============================================================================
// Embassy async tasks
// =============================================================================

#[embassy_executor::task]
async fn net_poll_task() {
    let s = unsafe { G_NET.assume_init_mut() };
    let dhcp_handle = s.dhcp_handle;
    let icmp_handle = s.icmp_handle;
    let echo_handle = s.echo_handle;

    let mut dns_server = DEFAULT_DNS;
    let mut ping_sent = false;
    let mut ping_replied = false;

    loop {
        let ts = now();
        {
            let NetState {
                ref mut device,
                ref mut iface,
                ref mut sockets,
                ..
            } = *s;
            iface.poll(ts, device, sockets);
        }

        // Handle DHCP events
        {
            let dhcp = s.sockets.get_mut::<dhcpv4::Socket>(dhcp_handle);
            if let Some(event) = dhcp.poll() {
                match event {
                    dhcpv4::Event::Configured(cfg) => {
                        let cidr = cfg.address;
                        print(b"NET: DHCP: IP=");
                        print_ip(u32_from_ip(&cidr.address()));
                        print(b"/");
                        print_u32(cidr.prefix_len() as u32);

                        s.iface.update_ip_addrs(|addrs| {
                            if !addrs.is_empty() {
                                addrs[0] = IpCidr::Ipv4(cidr);
                            } else {
                                let _ = addrs.push(IpCidr::Ipv4(cidr));
                            }
                        });

                        if let Some(router) = cfg.router {
                            s.iface
                                .routes_mut()
                                .add_default_ipv4_route(router)
                                .ok();
                            print(b" GW=");
                            print_ip(u32_from_ip(&router));
                        }
                        if let Some(&dns) = cfg.dns_servers.iter().next() {
                            dns_server = u32_from_ip(&dns);
                            print(b" DNS=");
                            print_ip(dns_server);
                        }
                        print(b"\n");
                    }
                    dhcpv4::Event::Deconfigured => {
                        print(b"NET: DHCP deconfigured\n");
                        dns_server = DEFAULT_DNS;
                        s.iface.update_ip_addrs(|addrs| {
                            if !addrs.is_empty() {
                                addrs[0] =
                                    IpCidr::Ipv4(Ipv4Cidr::new(ip_from_u32(DEFAULT_IP), 24));
                            }
                        });
                    }
                }
            }
        }

        // Boot ping (coordinated by boot_ping_task via atomic)
        let phase = BOOT_PING_PHASE.load(Ordering::Acquire);
        if phase >= 1 && !ping_sent {
            let icmp = s.sockets.get_mut::<icmp::Socket>(icmp_handle);
            if icmp.can_send() {
                let echo = build_echo_request(PING_ID, 1);
                if icmp
                    .send_slice(&echo, IpAddress::Ipv4(ip_from_u32(PING_TARGET)))
                    .is_ok()
                {
                    print(b"NET: PING 8.8.8.8 seq=1\n");
                    ping_sent = true;
                }
            }
        }

        if ping_sent && !ping_replied {
            let icmp = s.sockets.get_mut::<icmp::Socket>(icmp_handle);
            while icmp.can_recv() {
                let mut buf = [0u8; 128];
                if let Ok((n, addr)) = icmp.recv_slice(&mut buf) {
                    if n >= 8 && buf[0] == 0 {
                        let id = u16::from_be_bytes([buf[4], buf[5]]);
                        if id == PING_ID {
                            let seq = u16::from_be_bytes([buf[6], buf[7]]);
                            print(b"NET: PONG from ");
                            if let IpAddress::Ipv4(ip4) = addr {
                                print_ip(u32_from_ip(&ip4));
                            }
                            print(b" seq=");
                            print_u32(seq as u32);
                            print(b" -- google is alive!\n");
                            ping_replied = true;
                            BOOT_PING_PHASE.store(2, Ordering::Release);
                        }
                    }
                } else {
                    break;
                }
            }
        }

        // TCP echo server
        {
            let echo = s.sockets.get_mut::<tcp::Socket>(echo_handle);
            if echo.may_recv() {
                let mut buf = [0u8; 2048];
                if let Ok(n) = echo.recv_slice(&mut buf) {
                    if n > 0 {
                        let _ = echo.send_slice(&buf[..n]);
                    }
                }
            }
            if !echo.is_active() && !echo.is_listening() {
                let _ = echo.listen(TCP_ECHO_PORT);
            }
        }

        // Process IPC commands (non-blocking)
        let cmd = IPC_CMD.load(Ordering::Acquire);
        if cmd != 0 {
            let NetState {
                ref mut device,
                ref mut iface,
                ref mut sockets,
                ..
            } = *s;
            let result = process_ipc_cmd(
                cmd,
                iface,
                device,
                sockets,
                dns_server,
                icmp_handle,
            );
            IPC_RESULT.store(result, Ordering::Release);
            IPC_CMD.store(0, Ordering::Release);
        }

        async_yield().await;
        s.device.net.ack_irq();
    }
}

#[embassy_executor::task]
async fn boot_ping_task() {
    // Wait for network stack to initialize (DHCP, ARP, etc.)
    for _ in 0..50 {
        async_yield().await;
    }

    // Signal main poll task to send boot ping
    BOOT_PING_PHASE.store(1, Ordering::Release);
    print(b"NET: [async] boot ping requested\n");

    // Wait for ping reply
    while BOOT_PING_PHASE.load(Ordering::Acquire) != 2 {
        async_yield().await;
    }
    print(b"NET: [async] boot ping completed!\n");
}

// =============================================================================
// IPC command processing via smoltcp sockets
// =============================================================================

fn process_ipc_cmd(
    cmd: u64,
    iface: &mut Interface,
    device: &mut VirtioDevice,
    sockets: &mut SocketSet,
    dns_server: u32,
    icmp_handle: SocketHandle,
) -> u64 {
    let arg0 = IPC_ARG0.load(Ordering::Acquire);
    let arg1 = IPC_ARG1.load(Ordering::Acquire);
    let arg2 = IPC_ARG2.load(Ordering::Acquire);

    match cmd {
        CMD_PING => {
            let dst_ip = arg0 as u32;
            let ping_seq = arg1 as u16;

            let echo = build_echo_request(PING_ID, ping_seq);
            {
                let icmp = sockets.get_mut::<icmp::Socket>(icmp_handle);
                if icmp
                    .send_slice(&echo, IpAddress::Ipv4(ip_from_u32(dst_ip)))
                    .is_err()
                {
                    return 0;
                }
            }

            for _ in 0..600 {
                iface.poll(now(), device, sockets);
                let icmp = sockets.get_mut::<icmp::Socket>(icmp_handle);
                if icmp.can_recv() {
                    let mut buf = [0u8; 128];
                    if let Ok((n, _)) = icmp.recv_slice(&mut buf) {
                        if n >= 8 && buf[0] == 0 {
                            let id = u16::from_be_bytes([buf[4], buf[5]]);
                            let seq = u16::from_be_bytes([buf[6], buf[7]]);
                            if id == PING_ID && seq == ping_seq {
                                return 1 | (64u64 << 32);
                            }
                        }
                    }
                }
                sys::yield_now();
            }
            0
        }

        CMD_DNS_QUERY => {
            let name_len = arg1 as usize;
            let name = unsafe {
                core::slice::from_raw_parts(
                    core::ptr::addr_of!(IPC_DATA_BUF) as *const u8,
                    name_len.min(48),
                )
            };

            // Find or create UDP socket on port 53
            let slot = find_udp_slot(53).or_else(|| {
                let slot = alloc_udp_slot()?;
                let rx = udp::PacketBuffer::new(
                    alloc::vec![udp::PacketMetadata::EMPTY; 4],
                    alloc::vec![0u8; 1024],
                );
                let tx = udp::PacketBuffer::new(
                    alloc::vec![udp::PacketMetadata::EMPTY; 4],
                    alloc::vec![0u8; 1024],
                );
                let mut udp_sock = udp::Socket::new(rx, tx);
                if udp_sock.bind(53).is_err() {
                    return None;
                }
                let handle = sockets.add(udp_sock);
                unsafe {
                    UDP_SLOTS[slot] = (Some(handle), 53);
                }
                Some(slot)
            });

            if let Some(slot) = slot {
                let handle = unsafe { UDP_SLOTS[slot].0.unwrap() };
                let mut query = [0u8; 512];
                let qlen = build_dns_query(name, &mut query);
                if qlen > 0 {
                    {
                        let sock = sockets.get_mut::<udp::Socket>(handle);
                        let ep =
                            IpEndpoint::new(IpAddress::Ipv4(ip_from_u32(dns_server)), 53);
                        let _ = sock.send_slice(&query[..qlen], ep);
                    }

                    for _ in 0..200 {
                        iface.poll(now(), device, sockets);
                        let sock = sockets.get_mut::<udp::Socket>(handle);
                        if sock.can_recv() {
                            let mut buf = [0u8; 512];
                            if let Ok((n, _)) = sock.recv_slice(&mut buf) {
                                if let Some(ip) = parse_dns_response(&buf[..n]) {
                                    return ip as u64;
                                }
                            }
                        }
                        sys::yield_now();
                    }
                }
            }
            0
        }

        CMD_TCP_CONNECT => {
            let dst_ip = arg0 as u32;
            let dst_port = arg1 as u16;
            let local_port = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed) as u16;

            if let Some(slot) = alloc_tcp_slot() {
                // 131072 = 128KB RX buffer: SLIRP doesn't respect TCP flow control
                // and sends data in bursts. Large buffer prevents dropped segments.
                let rx = tcp::SocketBuffer::new(alloc::vec![0u8; 131072]);
                let tx = tcp::SocketBuffer::new(alloc::vec![0u8; 4096]);
                let tcp_sock = tcp::Socket::new(rx, tx);
                let handle = sockets.add(tcp_sock);

                {
                    let cx = iface.context();
                    let sock = sockets.get_mut::<tcp::Socket>(handle);
                    let remote =
                        IpEndpoint::new(IpAddress::Ipv4(ip_from_u32(dst_ip)), dst_port);
                    if sock.connect(cx, remote, local_port).is_err() {
                        sockets.remove(handle);
                        return (-1i64) as u64;
                    }
                }
                unsafe {
                    TCP_SLOTS[slot] = Some(handle);
                }

                // Wait for connection (up to ~5 seconds for real internet)
                // Wait for connection (up to ~5 seconds for real internet)
                for _i in 0..5000u32 {
                    iface.poll(now(), device, sockets);
                    let sock = sockets.get_mut::<tcp::Socket>(handle);
                    if sock.is_active() && sock.may_send() {
                        return slot as u64;
                    }
                    let st = sock.state();
                    if st == tcp::State::Closed {
                        break;
                    }
                    sys::yield_now();
                }

                // Failed
                sockets.remove(handle);
                unsafe {
                    TCP_SLOTS[slot] = None;
                }
                (-1i64) as u64
            } else {
                (-1i64) as u64
            }
        }

        CMD_TCP_SEND => {
            let conn_id = arg0 as usize;
            let data_len = arg2 as usize;
            if conn_id >= MAX_TCP {
                return (-1i64) as u64;
            }
            let handle = match unsafe { TCP_SLOTS[conn_id] } {
                Some(h) => h,
                None => return (-1i64) as u64,
            };
            let data = unsafe {
                core::slice::from_raw_parts(
                    core::ptr::addr_of!(IPC_DATA_BUF) as *const u8,
                    data_len.min(4096),
                )
            };
            let sock = sockets.get_mut::<tcp::Socket>(handle);
            match sock.send_slice(data) {
                Ok(n) => {
                    iface.poll(now(), device, sockets);
                    n as u64
                }
                Err(_) => (-1i64) as u64,
            }
        }

        CMD_TCP_RECV => {
            let conn_id = arg0 as usize;
            let offset = arg2 as usize; // 0 = fresh read, >0 = serve from buffer
            if conn_id >= MAX_TCP {
                return 0;
            }

            // If offset > 0, serve from previously-stored IPC_DATA_BUF (no socket read)
            if offset > 0 {
                let total = IPC_TCP_RECV_TOTAL.load(core::sync::atomic::Ordering::Acquire) as usize;
                if offset >= total { return 0; }
                return (total - offset) as u64;
            }

            let handle = match unsafe { TCP_SLOTS[conn_id] } {
                Some(h) => h,
                None => return 0,
            };

            // Read from smoltcp: use caller's requested max (regs[3]) if >0, else 4096.
            // This prevents over-consuming from the smoltcp buffer when the caller
            // only needs a small amount (e.g., HTTP header reads).
            let caller_want = IPC_ARG3.load(core::sync::atomic::Ordering::Acquire) as usize;
            let max_len = if caller_want > 0 && caller_want <= 4096 { caller_want } else { 4096 };

            // Try immediate read
            {
                let sock = sockets.get_mut::<tcp::Socket>(handle);
                if sock.can_recv() {
                    let ipc_buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8,
                            max_len,
                        )
                    };
                    if let Ok(n) = sock.recv_slice(ipc_buf) {
                        if n > 0 {
                            // Flush ACK/window update immediately so server sends more data
                            drop(sock);
                            iface.poll(now(), device, sockets);
                            IPC_TCP_RECV_TOTAL.store(n as u64, core::sync::atomic::Ordering::Release);
                            return n as u64;
                        }
                    }
                }
            }
            // Poll for incoming data (with ACK flush after each read)
            for _ in 0..2000u32 {
                iface.poll(now(), device, sockets);
                device.net.ack_irq();
                let sock = sockets.get_mut::<tcp::Socket>(handle);
                if sock.can_recv() {
                    let ipc_buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8,
                            max_len,
                        )
                    };
                    if let Ok(n) = sock.recv_slice(ipc_buf) {
                        if n > 0 {
                            drop(sock);
                            iface.poll(now(), device, sockets); // flush ACK
                            IPC_TCP_RECV_TOTAL.store(n as u64, core::sync::atomic::Ordering::Release);
                            return n as u64;
                        }
                    }
                }
                let sock2 = sockets.get_mut::<tcp::Socket>(handle);
                if !sock2.is_active() {
                    return 0xFFFE; // EOF sentinel
                }
                sys::yield_now();
            }
            0
        }

        CMD_TCP_CLOSE => {
            let conn_id = arg0 as usize;
            if conn_id < MAX_TCP {
                if let Some(handle) = unsafe { TCP_SLOTS[conn_id] } {
                    let sock = sockets.get_mut::<tcp::Socket>(handle);
                    sock.abort();
                    iface.poll(now(), device, sockets);
                    sockets.remove(handle);
                    unsafe {
                        TCP_SLOTS[conn_id] = None;
                    }
                }
            }
            0
        }

        CMD_TRACEROUTE_HOP => {
            let dst_ip = arg0 as u32;
            let ttl = arg1 as u8;

            {
                let icmp = sockets.get_mut::<icmp::Socket>(icmp_handle);
                icmp.set_hop_limit(Some(ttl));
                let echo = build_echo_request(PING_ID, ttl as u16);
                if icmp
                    .send_slice(&echo, IpAddress::Ipv4(ip_from_u32(dst_ip)))
                    .is_err()
                {
                    icmp.set_hop_limit(None);
                    return 0;
                }
            }

            let mut result: u64 = 0;
            for _ in 0..200 {
                iface.poll(now(), device, sockets);
                let icmp = sockets.get_mut::<icmp::Socket>(icmp_handle);
                if icmp.can_recv() {
                    let mut buf = [0u8; 128];
                    if let Ok((_n, addr)) = icmp.recv_slice(&mut buf) {
                        let IpAddress::Ipv4(ip4) = addr;
                        let src = u32_from_ip(&ip4);
                        if buf[0] == 11 {
                            // Time Exceeded
                            result = src as u64;
                            break;
                        } else if buf[0] == 0 {
                            // Echo Reply — reached destination
                            result = src as u64 | (1u64 << 32);
                            break;
                        }
                    }
                }
                sys::yield_now();
            }

            let icmp = sockets.get_mut::<icmp::Socket>(icmp_handle);
            icmp.set_hop_limit(None);
            result
        }

        CMD_UDP_BIND => {
            let port = arg0 as u16;
            if let Some(slot) = alloc_udp_slot() {
                let rx = udp::PacketBuffer::new(
                    alloc::vec![udp::PacketMetadata::EMPTY; 8],
                    alloc::vec![0u8; 2048],
                );
                let tx = udp::PacketBuffer::new(
                    alloc::vec![udp::PacketMetadata::EMPTY; 8],
                    alloc::vec![0u8; 2048],
                );
                let mut udp_sock = udp::Socket::new(rx, tx);
                if udp_sock.bind(port).is_ok() {
                    let handle = sockets.add(udp_sock);
                    unsafe {
                        UDP_SLOTS[slot] = (Some(handle), port);
                    }
                }
            }
            0
        }

        CMD_UDP_SENDTO => {
            // Packed: tag(32-bit) = CMD | (data_len<<16)
            // arg0 = regs[0] = dst_ip(32) | dst_port(16@32) | src_port(16@48)
            let raw_tag = IPC_RAW_TAG.load(Ordering::Acquire);
            let dst_ip = (arg0 & 0xFFFFFFFF) as u32;
            let dst_port = ((arg0 >> 32) & 0xFFFF) as u16;
            let src_port = ((arg0 >> 48) & 0xFFFF) as u16;
            let data_len = (((raw_tag >> 16) & 0xFFFF) as usize).min(56);

            let data = unsafe {
                core::slice::from_raw_parts(
                    core::ptr::addr_of!(IPC_DATA_BUF) as *const u8,
                    data_len,
                )
            };

            let slot = find_udp_slot(src_port).or_else(|| {
                let slot = alloc_udp_slot()?;
                let rx = udp::PacketBuffer::new(
                    alloc::vec![udp::PacketMetadata::EMPTY; 4],
                    alloc::vec![0u8; 1024],
                );
                let tx = udp::PacketBuffer::new(
                    alloc::vec![udp::PacketMetadata::EMPTY; 4],
                    alloc::vec![0u8; 1024],
                );
                let mut udp_sock = udp::Socket::new(rx, tx);
                if udp_sock.bind(src_port).is_err() {
                    return None;
                }
                let handle = sockets.add(udp_sock);
                unsafe {
                    UDP_SLOTS[slot] = (Some(handle), src_port);
                }
                Some(slot)
            });

            if let Some(slot) = slot {
                let handle = unsafe { UDP_SLOTS[slot].0.unwrap() };
                let sock = sockets.get_mut::<udp::Socket>(handle);
                let ep = IpEndpoint::new(IpAddress::Ipv4(ip_from_u32(dst_ip)), dst_port);
                let _ = sock.send_slice(data, ep);
                iface.poll(now(), device, sockets);
                data_len as u64
            } else {
                0
            }
        }

        CMD_UDP_RECV => {
            let port = arg0 as u16;
            let offset = arg2 as usize;

            // If offset > 0, return next chunk from previously-stored IPC_DATA_BUF
            if offset > 0 {
                let total = IPC_UDP_RECV_TOTAL.load(Ordering::Acquire) as usize;
                if offset >= total { return 0; }
                // Return remaining bytes from stored buffer (IPC handler copies from offset)
                return (total - offset) as u64;
            }

            // offset == 0: poll for new datagram
            let max_len = 512usize;
            let slot = match find_udp_slot(port) {
                Some(s) => s,
                None => { return 0; },
            };
            let handle = unsafe { UDP_SLOTS[slot].0.unwrap() };

            // Check buffered data first
            {
                let sock = sockets.get_mut::<udp::Socket>(handle);
                if sock.can_recv() {
                    let ipc_buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8,
                            max_len,
                        )
                    };
                    if let Ok((n, _ep)) = sock.recv_slice(ipc_buf) {
                        IPC_UDP_RECV_TOTAL.store(n as u64, Ordering::Release);
                        return n as u64;
                    }
                }
            }

            // Poll for new data — short timeout to avoid blocking other IPC.
            // Init's recvfrom retries many times; each call here is ~5ms max.
            for _iter in 0..500u32 {
                sys::yield_now();
                device.net.ack_irq();
                iface.poll(now(), device, sockets);
                let sock = sockets.get_mut::<udp::Socket>(handle);
                if sock.can_recv() {
                    let ipc_buf = unsafe {
                        core::slice::from_raw_parts_mut(
                            core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8,
                            max_len,
                        )
                    };
                    if let Ok((n, _ep)) = sock.recv_slice(ipc_buf) {
                        IPC_UDP_RECV_TOTAL.store(n as u64, Ordering::Release);
                        return n as u64;
                    }
                }
            }
            0
        }

        CMD_TCP_STATUS => {
            let conn_id = arg0 as usize;
            if conn_id >= MAX_TCP {
                return 0;
            }
            match unsafe { TCP_SLOTS[conn_id] } {
                Some(handle) => {
                    let sock = sockets.get_mut::<tcp::Socket>(handle);
                    let recv_avail = sock.recv_queue() as u64;
                    let connected =
                        if sock.is_active() && sock.may_send() { 1u64 } else { 0u64 };
                    recv_avail | (connected << 32)
                }
                None => 0,
            }
        }

        CMD_UDP_HAS_DATA => {
            // Non-destructive check: does the UDP socket on this port have data?
            // yield+ack_irq gives QEMU's event loop time to deliver SLIRP's
            // DNS response to the virtio RX queue before we poll.
            let port = arg0 as u16;
            sys::yield_now();
            device.net.ack_irq();
            iface.poll(now(), device, sockets);
            if let Some(slot) = find_udp_slot(port) {
                let handle = unsafe { UDP_SLOTS[slot].0.unwrap() };
                let sock = sockets.get_mut::<udp::Socket>(handle);
                if sock.can_recv() { 1 } else { 0 }
            } else {
                0
            }
        }

        CMD_NET_MIRROR => {
            NET_MIRROR.store(arg0, Ordering::Release);
            if arg0 != 0 {
                print(b"NET: packet mirroring ENABLED\n");
            } else {
                print(b"NET: packet mirroring DISABLED\n");
            }
            0
        }

        _ => (-1i64) as u64,
    }
}

// =============================================================================
// IPC handler thread — blocks on recv, posts to atomic queue
// =============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn ipc_handler_thread() -> ! {
    let ep_cap = IPC_EP_CAP.load(Ordering::Acquire);
    print(b"NET: IPC handler thread started\n");

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let cmd = msg.tag & 0xFFFF; // low 16 bits = command
        let arg0 = msg.regs[0];
        let arg1 = msg.regs[1];
        let arg2 = msg.regs[2];

        // Copy inline data from IPC regs to shared buffer
        if cmd == CMD_DNS_QUERY {
            let avail = (arg1 as usize).min(48);
            unsafe {
                let src = &msg.regs[2] as *const u64 as *const u8;
                core::ptr::copy_nonoverlapping(
                    src,
                    core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8,
                    avail,
                );
            }
        } else if cmd == CMD_TCP_SEND {
            let avail = (arg2 as usize).min(40);
            unsafe {
                let src = &msg.regs[3] as *const u64 as *const u8;
                core::ptr::copy_nonoverlapping(
                    src,
                    core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8,
                    avail,
                );
            }
        } else if cmd == CMD_UDP_SENDTO {
            // Packed: tag(32-bit) = CMD | (data_len<<16)
            // regs[0] = dst_ip|dst_port|src_port, regs[1..7] = data (56 bytes max)
            let avail = (((msg.tag >> 16) & 0xFFFF) as usize).min(56);
            unsafe {
                let src = &msg.regs[1] as *const u64 as *const u8;
                core::ptr::copy_nonoverlapping(
                    src,
                    core::ptr::addr_of_mut!(IPC_DATA_BUF) as *mut u8,
                    avail,
                );
            }
        }

        // Post command
        IPC_ARG0.store(arg0, Ordering::Release);
        IPC_ARG1.store(arg1, Ordering::Release);
        IPC_ARG2.store(arg2, Ordering::Release);
        IPC_ARG3.store(msg.regs[3], Ordering::Release);
        IPC_RAW_TAG.store(msg.tag, Ordering::Release);
        IPC_RESULT.store(0, Ordering::Release);
        IPC_CMD.store(cmd, Ordering::Release);

        // Wait for main loop to process
        loop {
            if IPC_CMD.load(Ordering::Acquire) == 0 {
                break;
            }
            sys::yield_now();
        }

        let result = IPC_RESULT.load(Ordering::Acquire);

        // Build reply
        let mut reply = IpcMsg::empty();
        reply.regs[0] = result;

        // TCP_RECV / UDP_RECV: copy data into reply regs
        if (cmd == CMD_TCP_RECV || cmd == CMD_UDP_RECV) && result > 0 {
            // Pass through EOF sentinel WITHOUT clamping or copying data
            if result == 0xFFFE {
                reply.tag = 0xFFFE;
            } else {
                let offset = if cmd == CMD_UDP_RECV || cmd == CMD_TCP_RECV { arg2 as usize } else { 0 };
                let n = (result as usize).min(64);
                reply.tag = n as u64;
                unsafe {
                    let src = (core::ptr::addr_of!(IPC_DATA_BUF) as *const u8).add(offset);
                    let dst = &mut reply.regs[0] as *mut u64 as *mut u8;
                    core::ptr::copy_nonoverlapping(src, dst, n);
                }
            }
        }

        // TCP_STATUS: unpack into two regs
        if cmd == CMD_TCP_STATUS {
            reply.regs[0] = result & 0xFFFFFFFF;
            reply.regs[1] = result >> 32;
        }

        let _ = sys::send(ep_cap, &reply);
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
    loop {
        sys::yield_now();
    }
}
