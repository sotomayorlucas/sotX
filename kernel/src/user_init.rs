//! Embedded init process — two userspace threads for IPC testing.
//!
//! **Sender** (`.user_init`): prints "INIT\n", sends IPC message with
//! chars ['I','P','C','!'] as msg regs 0–3, prints "OK\n", yields forever.
//!
//! **Receiver** (`.user_recv`): does SYS_RECV on endpoint 0, prints the
//! 4 received characters + newline, yields forever.
//!
//! Register convention for IPC syscalls:
//!   rax = syscall#, rdi = endpoint ID
//!   rsi = tag, rdx/r8/r9/r10/r12/r13/r14/r15 = msg regs 0–7

extern "C" {
    static user_init_start: u8;
    static user_init_end: u8;
    static user_recv_start: u8;
    static user_recv_end: u8;
    static user_kb_start: u8;
    static user_kb_end: u8;
    static user_async_tx_start: u8;
    static user_async_tx_end: u8;
    static user_async_rx_start: u8;
    static user_async_rx_end: u8;
    static user_child_start: u8;
    static user_child_end: u8;
    static user_shm_tx_start: u8;
    static user_shm_tx_end: u8;
    static user_shm_rx_start: u8;
    static user_shm_rx_end: u8;
    static user_serial_start: u8;
    static user_serial_end: u8;
    static user_vmm_start: u8;
    static user_vmm_end: u8;
    static user_fault_test_start: u8;
    static user_fault_test_end: u8;
}

/// Return the sender (init) code as a byte slice.
pub fn init_code() -> &'static [u8] {
    unsafe {
        let start = &user_init_start as *const u8;
        let end = &user_init_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the receiver code as a byte slice.
pub fn recv_code() -> &'static [u8] {
    unsafe {
        let start = &user_recv_start as *const u8;
        let end = &user_recv_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the keyboard driver code as a byte slice.
pub fn kb_code() -> &'static [u8] {
    unsafe {
        let start = &user_kb_start as *const u8;
        let end = &user_kb_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the async channel producer code as a byte slice.
pub fn async_tx_code() -> &'static [u8] {
    unsafe {
        let start = &user_async_tx_start as *const u8;
        let end = &user_async_tx_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the async channel consumer code as a byte slice.
pub fn async_rx_code() -> &'static [u8] {
    unsafe {
        let start = &user_async_rx_start as *const u8;
        let end = &user_async_rx_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the child thread code as a byte slice.
pub fn child_code() -> &'static [u8] {
    unsafe {
        let start = &user_child_start as *const u8;
        let end = &user_child_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the shared-memory producer code as a byte slice.
pub fn shm_tx_code() -> &'static [u8] {
    unsafe {
        let start = &user_shm_tx_start as *const u8;
        let end = &user_shm_tx_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the shared-memory consumer code as a byte slice.
pub fn shm_rx_code() -> &'static [u8] {
    unsafe {
        let start = &user_shm_rx_start as *const u8;
        let end = &user_shm_rx_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the serial driver code as a byte slice.
pub fn serial_code() -> &'static [u8] {
    unsafe {
        let start = &user_serial_start as *const u8;
        let end = &user_serial_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the VMM server code as a byte slice.
pub fn vmm_code() -> &'static [u8] {
    unsafe {
        let start = &user_vmm_start as *const u8;
        let end = &user_vmm_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the fault test code as a byte slice.
pub fn fault_test_code() -> &'static [u8] {
    unsafe {
        let start = &user_fault_test_start as *const u8;
        let end = &user_fault_test_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

// ---------------------------------------------------------------------------
// Sender: prints "INIT\n", sends IPC('I','P','C','!'), prints "OK\n"
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_init, \"ax\"",
    ".global user_init_start",
    ".global user_init_end",
    "user_init_start:",

    // --- Print "INIT\n" ---
    "    mov rax, 255",
    "    mov rdi, 0x49",       // 'I'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4E",       // 'N'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x49",       // 'I'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x54",       // 'T'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- SYS_THREAD_CREATE(40): spawn child at 0x405000 with stack at 0x80B000 ---
    "    mov rax, 40",         // SYS_THREAD_CREATE
    "    mov rdi, 0x405000",   // child entry RIP
    "    mov rsi, 0x80B000",   // child stack RSP (top of 0x80A000 page)
    "    syscall",
    // rax = thread cap_id (cap 4)

    // --- SYS_CAP_GRANT(30): mint read-only copy of endpoint cap 0 ---
    "    mov rax, 30",         // SYS_CAP_GRANT
    "    xor rdi, rdi",        // source = cap 0 (endpoint, ALL rights)
    "    mov rsi, 0x01",       // rights mask = READ only
    "    syscall",
    // rax = new cap_id (cap 5, read-only endpoint)

    // --- SYS_SEND(1): ep=0, tag=0, regs[0]='I', regs[1]='P', regs[2]='C', regs[3]='!' ---
    "    mov rax, 1",          // SYS_SEND
    "    xor rdi, rdi",        // endpoint 0
    "    xor rsi, rsi",        // tag = 0
    "    mov rdx, 0x49",       // 'I' → msg reg 0
    "    mov r8,  0x50",       // 'P' → msg reg 1
    "    mov r9,  0x43",       // 'C' → msg reg 2
    "    mov r10, 0x21",       // '!' → msg reg 3
    "    xor r12, r12",        // msg reg 4 = 0
    "    xor r13, r13",        // msg reg 5 = 0
    "    xor r14, r14",        // msg reg 6 = 0
    "    xor r15, r15",        // msg reg 7 = 0
    "    syscall",

    // --- Print "OK\n" ---
    "    mov rax, 255",
    "    mov rdi, 0x4F",       // 'O'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4B",       // 'K'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- Yield forever ---
    "0:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 0b",

    "user_init_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Receiver: SYS_RECV(ep=0), print 4 chars from msg regs + newline
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_recv, \"ax\"",
    ".global user_recv_start",
    ".global user_recv_end",
    "user_recv_start:",

    // --- SYS_RECV(2): ep=0 ---
    "    mov rax, 2",          // SYS_RECV
    "    xor rdi, rdi",        // endpoint 0
    "    syscall",

    // On return: rdx='I', r8='P', r9='C', r10='!'
    // Save received regs (rdx, r8, r9, r10) to callee-saved regs
    "    mov r12, rdx",        // 'I'
    "    mov r13, r8",         // 'P'
    "    mov r14, r9",         // 'C'
    "    mov r15, r10",        // '!'

    // Print r12 ('I')
    "    mov rax, 255",
    "    mov rdi, r12",
    "    syscall",

    // Print r13 ('P')
    "    mov rax, 255",
    "    mov rdi, r13",
    "    syscall",

    // Print r14 ('C')
    "    mov rax, 255",
    "    mov rdi, r14",
    "    syscall",

    // Print r15 ('!')
    "    mov rax, 255",
    "    mov rdi, r15",
    "    syscall",

    // Print newline
    "    mov rax, 255",
    "    mov rdi, 0x0A",
    "    syscall",

    // --- Yield forever ---
    "0:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 0b",

    "user_recv_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Keyboard driver: notification-based IRQ handling.
//   cap 2 = Irq { line: 1 }, cap 3 = IoPort { base: 0x60, count: 1 },
//   cap 5 = Notification { id: 1 } (keyboard IRQ notification)
// Flow: IRQ_REGISTER(cap2, cap5) → loop { NOTIFY_WAIT(cap5), PORT_IN(cap3, 0x60), IRQ_ACK(cap2) }
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_kb, \"ax\"",
    ".global user_kb_start",
    ".global user_kb_end",
    "user_kb_start:",

    // --- SYS_IRQ_REGISTER(50): bind IRQ 1 → notification 1 ---
    "    mov rax, 50",         // SYS_IRQ_REGISTER
    "    mov rdi, 2",          // cap 2 = IRQ 1
    "    mov rsi, 5",          // cap 5 = Notification 1 (keyboard)
    "    syscall",

    // --- Print 'K' 'B' '\n' to confirm registration ---
    "    mov rax, 255",
    "    mov rdi, 0x4B",       // 'K'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x42",       // 'B'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- Main loop: wait for notification, read scancode, ack IRQ ---
    "2:",
    "    mov rax, 71",         // SYS_NOTIFY_WAIT
    "    mov rdi, 5",          // cap 5 = Notification 1
    "    syscall",

    // Read scancode from port 0x60
    "    mov rax, 60",         // SYS_PORT_IN
    "    mov rdi, 3",          // cap 3 = I/O port 0x60
    "    mov rsi, 0x60",       // port address
    "    syscall",
    "    mov r12, rax",        // save scancode in callee-saved r12

    // Unmask IRQ line
    "    mov rax, 51",         // SYS_IRQ_ACK
    "    mov rdi, 2",          // cap 2 = IRQ 1
    "    syscall",

    // Print "K:"
    "    mov rax, 255",
    "    mov rdi, 0x4B",       // 'K'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x3A",       // ':'
    "    syscall",

    // Print high hex nibble
    "    mov rdi, r12",
    "    shr rdi, 4",
    "    and rdi, 0x0F",
    "    lea rax, [rip + .Lhex_kb_table]",
    "    movzx rdi, byte ptr [rax + rdi]",
    "    mov rax, 255",
    "    syscall",

    // Print low hex nibble
    "    mov rdi, r12",
    "    and rdi, 0x0F",
    "    lea rax, [rip + .Lhex_kb_table]",
    "    movzx rdi, byte ptr [rax + rdi]",
    "    mov rax, 255",
    "    syscall",

    // Print newline
    "    mov rax, 255",
    "    mov rdi, 0x0A",
    "    syscall",

    "    jmp 2b",

    // Hex lookup table
    ".Lhex_kb_table: .ascii \"0123456789ABCDEF\"",

    "user_kb_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Async channel producer: sends 'A','S','Y','N','C' as 5 messages on ch 0,
// prints "TX\n", yields forever.
// Uses SYS_CHANNEL_SEND (5): rax=5, rdi=channel, rsi=tag (the char).
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_async_tx, \"ax\"",
    ".global user_async_tx_start",
    ".global user_async_tx_end",
    "user_async_tx_start:",

    // Use r12 as index, rbx as pointer into char table
    "    xor r12, r12",            // r12 = counter = 0

    "1:",
    "    cmp r12, 5",
    "    jge 2f",

    // Load character from table
    "    lea rbx, [rip + .Lasync_chars]",
    "    movzx rsi, byte ptr [rbx + r12]",  // rsi = tag = char

    // SYS_CHANNEL_SEND(5): rdi=1 (cap 1 = channel 0), rsi=tag
    "    mov rax, 5",
    "    mov rdi, 1",              // cap 1 = channel 0
    "    xor rdx, rdx",
    "    xor r8, r8",
    "    xor r9, r9",
    "    xor r10, r10",
    // r12 is our counter — save before syscall clobbers it
    "    push r12",
    "    push rbx",
    "    xor r13, r13",
    "    xor r14, r14",
    "    xor r15, r15",
    "    syscall",
    "    pop rbx",
    "    pop r12",

    "    inc r12",
    "    jmp 1b",

    "2:",
    // --- Print "TX\n" ---
    "    mov rax, 255",
    "    mov rdi, 0x54",           // 'T'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x58",           // 'X'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",           // '\n'
    "    syscall",

    // --- Yield forever ---
    "3:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 3b",

    ".Lasync_chars: .ascii \"ASYNC\"",

    "user_async_tx_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Async channel consumer: receives 5 messages from ch 0, prints each tag
// char, prints "\n", yields forever.
// Uses SYS_CHANNEL_RECV (6): rax=6, rdi=channel. Returns tag in rsi.
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_async_rx, \"ax\"",
    ".global user_async_rx_start",
    ".global user_async_rx_end",
    "user_async_rx_start:",

    "    xor rbx, rbx",            // rbx = counter = 0

    "1:",
    "    cmp rbx, 5",
    "    jge 2f",

    // SYS_CHANNEL_RECV(6): rdi=1 (cap 1 = channel 0)
    "    mov rax, 6",
    "    mov rdi, 1",              // cap 1 = channel 0
    "    syscall",

    // On return: rsi = tag (the char). Save it.
    "    mov r12, rsi",

    // Print the character
    "    mov rax, 255",
    "    mov rdi, r12",
    "    syscall",

    "    inc rbx",
    "    jmp 1b",

    "2:",
    // Print newline
    "    mov rax, 255",
    "    mov rdi, 0x0A",
    "    syscall",

    // --- Yield forever ---
    "3:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 3b",

    "user_async_rx_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Child thread: prints "SPAWN\n", yields forever.
// Spawned dynamically from sender via SYS_THREAD_CREATE.
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_child, \"ax\"",
    ".global user_child_start",
    ".global user_child_end",
    "user_child_start:",

    // --- Print "SPAWN\n" ---
    "    mov rax, 255",
    "    mov rdi, 0x53",       // 'S'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x50",       // 'P'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x41",       // 'A'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x57",       // 'W'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4E",       // 'N'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- Yield forever ---
    "0:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 0b",

    "user_child_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Shared-memory producer: writes 'Z','E','R','O' to 0x500000, signals
// notification (cap 4), prints "TX0\n", yields forever.
// Zero-copy: kernel never touches the data at 0x500000.
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_shm_tx, \"ax\"",
    ".global user_shm_tx_start",
    ".global user_shm_tx_end",
    "user_shm_tx_start:",

    // Write 'Z','E','R','O' to shared page at 0x500000
    "    mov rdi, 0x500000",
    "    mov byte ptr [rdi],     0x5A",  // 'Z'
    "    mov byte ptr [rdi + 1], 0x45",  // 'E'
    "    mov byte ptr [rdi + 2], 0x52",  // 'R'
    "    mov byte ptr [rdi + 3], 0x4F",  // 'O'

    // SYS_NOTIFY_SIGNAL(72): cap 4 = notification 0
    "    mov rax, 72",
    "    mov rdi, 4",
    "    syscall",

    // --- Print "TX0\n" ---
    "    mov rax, 255",
    "    mov rdi, 0x54",           // 'T'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x58",           // 'X'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x30",           // '0'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",           // '\n'
    "    syscall",

    // --- Yield forever ---
    "0:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 0b",

    "user_shm_tx_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Shared-memory consumer: waits on notification (cap 4), reads 4 bytes from
// 0x500000, prints them + newline ("ZERO\n"), yields forever.
// Zero-copy: kernel never touches the data at 0x500000.
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_shm_rx, \"ax\"",
    ".global user_shm_rx_start",
    ".global user_shm_rx_end",
    "user_shm_rx_start:",

    // SYS_NOTIFY_WAIT(71): cap 4 = notification 0
    "    mov rax, 71",
    "    mov rdi, 4",
    "    syscall",

    // Read 4 bytes from shared page at 0x500000
    "    mov rsi, 0x500000",

    // Print byte 0 ('Z')
    "    movzx rdi, byte ptr [rsi]",
    "    mov rax, 255",
    "    syscall",

    // Print byte 1 ('E')
    "    mov rsi, 0x500000",
    "    movzx rdi, byte ptr [rsi + 1]",
    "    mov rax, 255",
    "    syscall",

    // Print byte 2 ('R')
    "    mov rsi, 0x500000",
    "    movzx rdi, byte ptr [rsi + 2]",
    "    mov rax, 255",
    "    syscall",

    // Print byte 3 ('O')
    "    mov rsi, 0x500000",
    "    movzx rdi, byte ptr [rsi + 3]",
    "    mov rax, 255",
    "    syscall",

    // Print newline
    "    mov rax, 255",
    "    mov rdi, 0x0A",
    "    syscall",

    // --- Yield forever ---
    "0:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 0b",

    "user_shm_rx_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Serial input driver: initializes COM1 receive interrupts, loops on
// NOTIFY_WAIT → read LSR/data → IRQ_ACK → print "S:XX\n".
//   cap 6 = Irq { line: 4 }, cap 7 = IoPort { base: 0x3F8, count: 8 },
//   cap 8 = Notification { id: 2 } (serial IRQ notification)
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_serial, \"ax\"",
    ".global user_serial_start",
    ".global user_serial_end",
    "user_serial_start:",

    // --- Setup COM1 for receive interrupts ---
    // PORT_OUT(cap7, 0x3F9, 0x01): IER = enable receive data available interrupt
    "    mov rax, 61",         // SYS_PORT_OUT
    "    mov rdi, 7",          // cap 7 = IoPort 0x3F8..0x3FF
    "    mov rsi, 0x3F9",      // IER register
    "    mov rdx, 0x01",       // enable RDA interrupt
    "    syscall",

    // PORT_OUT(cap7, 0x3FC, 0x0B): MCR = DTR + RTS + OUT2
    "    mov rax, 61",         // SYS_PORT_OUT
    "    mov rdi, 7",          // cap 7
    "    mov rsi, 0x3FC",      // MCR register
    "    mov rdx, 0x0B",       // DTR(1) + RTS(2) + OUT2(8) — OUT2 routes IRQ to PIC
    "    syscall",

    // --- IRQ_REGISTER(cap6, cap8): bind IRQ4 → Notification 2 ---
    "    mov rax, 50",         // SYS_IRQ_REGISTER
    "    mov rdi, 6",          // cap 6 = IRQ 4
    "    mov rsi, 8",          // cap 8 = Notification 2 (serial)
    "    syscall",

    // --- Print "COM1\n" to confirm registration ---
    "    mov rax, 255",
    "    mov rdi, 0x43",       // 'C'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4F",       // 'O'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4D",       // 'M'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x31",       // '1'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- Main loop: wait for IRQ, read data, ack, print ---
    "2:",
    "    mov rax, 71",         // SYS_NOTIFY_WAIT
    "    mov rdi, 8",          // cap 8 = Notification 2
    "    syscall",

    // Read LSR (0x3FD) to check data ready (bit 0)
    "    mov rax, 60",         // SYS_PORT_IN
    "    mov rdi, 7",          // cap 7 = COM1 ports
    "    mov rsi, 0x3FD",      // LSR register
    "    syscall",

    // Read received byte from data register (0x3F8)
    "    mov rax, 60",         // SYS_PORT_IN
    "    mov rdi, 7",          // cap 7
    "    mov rsi, 0x3F8",      // data register
    "    syscall",
    "    mov r12, rax",        // save received byte

    // Unmask IRQ4
    "    mov rax, 51",         // SYS_IRQ_ACK
    "    mov rdi, 6",          // cap 6 = IRQ 4
    "    syscall",

    // Print "S:"
    "    mov rax, 255",
    "    mov rdi, 0x53",       // 'S'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x3A",       // ':'
    "    syscall",

    // Print high hex nibble
    "    mov rdi, r12",
    "    shr rdi, 4",
    "    and rdi, 0x0F",
    "    lea rax, [rip + .Lhex_serial_table]",
    "    movzx rdi, byte ptr [rax + rdi]",
    "    mov rax, 255",
    "    syscall",

    // Print low hex nibble
    "    mov rdi, r12",
    "    and rdi, 0x0F",
    "    lea rax, [rip + .Lhex_serial_table]",
    "    movzx rdi, byte ptr [rax + rdi]",
    "    mov rax, 255",
    "    syscall",

    // Print newline
    "    mov rax, 255",
    "    mov rdi, 0x0A",
    "    syscall",

    "    jmp 2b",

    // Hex lookup table
    ".Lhex_serial_table: .ascii \"0123456789ABCDEF\"",

    "user_serial_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// VMM server: registers for page fault notifications, loops handling faults.
//   cap 9 = Notification { id: 3 } (fault notification)
// Flow: FAULT_REGISTER(cap9) → loop { NOTIFY_WAIT(cap9) → drain { FAULT_RECV
//   → FRAME_ALLOC → MAP(addr, frame_cap, WRITABLE) → THREAD_RESUME(tid) } }
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_vmm, \"ax\"",
    ".global user_vmm_start",
    ".global user_vmm_end",
    "user_vmm_start:",

    // --- SYS_FAULT_REGISTER(80): rdi = cap 9 (Notification 3) ---
    "    mov rax, 80",         // SYS_FAULT_REGISTER
    "    mov rdi, 9",          // cap 9 = fault notification
    "    syscall",

    // --- Main loop: wait for fault notification, then drain queue ---
    "1:",
    "    mov rax, 71",         // SYS_NOTIFY_WAIT
    "    mov rdi, 9",          // cap 9
    "    syscall",

    // --- Drain loop: try FAULT_RECV until WouldBlock ---
    "2:",
    "    mov rax, 81",         // SYS_FAULT_RECV
    "    syscall",
    "    test rax, rax",       // 0 = success, negative = WouldBlock
    "    jnz 1b",              // no more faults → go back to NOTIFY_WAIT

    // rdi = fault addr, rsi = fault code, rdx = tid
    // Save tid in r12, fault addr in r13
    "    mov r12, rdx",        // r12 = tid
    "    mov r13, rdi",        // r13 = fault addr

    // --- SYS_FRAME_ALLOC(20): allocate a physical frame ---
    "    mov rax, 20",         // SYS_FRAME_ALLOC
    "    syscall",
    "    mov r14, rax",        // r14 = frame cap_id

    // --- SYS_MAP(22): map frame at fault address ---
    // rdi = vaddr, rsi = frame_cap_id, rdx = user_flags (WRITABLE = bit 1)
    "    mov rax, 22",         // SYS_MAP
    "    mov rdi, r13",        // vaddr = fault addr (page-aligned by CPU)
    "    and rdi, -4096",      // ensure page-aligned
    "    mov rsi, r14",        // frame cap_id
    "    mov rdx, 2",          // WRITABLE flag (bit 1)
    "    syscall",

    // --- SYS_THREAD_RESUME(43): resume the faulted thread ---
    "    mov rax, 43",         // SYS_THREAD_RESUME
    "    mov rdi, r12",        // tid
    "    syscall",

    // --- Print 'V' 'M' 'M' '\n' ---
    "    mov rax, 255",
    "    mov rdi, 0x56",       // 'V'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4D",       // 'M'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4D",       // 'M'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // Try next fault in queue
    "    jmp 2b",

    "user_vmm_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Fault test: writes to unmapped address 0x600000 (triggers page fault),
// then prints "PF!\n" to prove the VMM handled it and we resumed.
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_fault_test, \"ax\"",
    ".global user_fault_test_start",
    ".global user_fault_test_end",
    "user_fault_test_start:",

    // Touch unmapped address → page fault → VMM handles → we resume here
    "    mov rdi, 0x600000",
    "    mov byte ptr [rdi], 0x42",

    // --- Print "PF!\n" ---
    "    mov rax, 255",
    "    mov rdi, 0x50",       // 'P'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x46",       // 'F'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x21",       // '!'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- Yield forever ---
    "0:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 0b",

    "user_fault_test_end:",
    ".previous",
);
