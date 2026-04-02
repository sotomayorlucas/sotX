#![no_std]
#![no_main]

use sotos_common::sys;

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_i64(mut n: i64) {
    if n < 0 {
        sys::debug_print(b'-');
        n = -n;
    }
    print_u64(n as u64);
}

fn print_u64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
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

fn report(name: &[u8], result: Result<u64, i64>) -> bool {
    print(b"  ");
    print(name);
    match result {
        Ok(val) => {
            print(b": OK (");
            print_u64(val);
            print(b")\n");
            true
        }
        Err(code) => {
            print(b": ERR (");
            print_i64(code);
            print(b")\n");
            false
        }
    }
}

fn report_unit(name: &[u8], result: Result<(), i64>) -> bool {
    report(name, result.map(|()| 0))
}

fn tally(ok: bool, pass: &mut u32, fail: &mut u32) {
    if ok { *pass += 1; } else { *fail += 1; }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"\n=== STYX TEST: SOT exokernel syscalls 300-310 ===\n\n");

    let mut pass = 0u32;
    let mut fail = 0u32;

    // so_create (300)
    let so_result = sys::so_create(1, 0);
    tally(report(b"so_create(1,0)", so_result), &mut pass, &mut fail);
    let so_cap = so_result.unwrap_or(0);

    // tx_begin (308)
    let tx_result = sys::tx_begin(0);
    tally(report(b"tx_begin(0)", tx_result), &mut pass, &mut fail);
    let tx_id = tx_result.unwrap_or(0);

    // tx_commit (309)
    tally(report_unit(b"tx_commit", sys::tx_commit(tx_id)), &mut pass, &mut fail);

    // so_observe (304)
    tally(report_unit(b"so_observe", sys::so_observe(so_cap, 0)), &mut pass, &mut fail);

    // tx_begin + tx_abort (310)
    let tx2_result = sys::tx_begin(0);
    tally(report(b"tx_begin(0) #2", tx2_result), &mut pass, &mut fail);
    tally(report_unit(b"tx_abort", sys::tx_abort(tx2_result.unwrap_or(0))), &mut pass, &mut fail);

    // sot_channel_create (307)
    tally(report(b"sot_channel_create(0)", sys::sot_channel_create(0)), &mut pass, &mut fail);

    // Summary
    print(b"\n--- Results: ");
    print_u64(pass as u64);
    print(b" pass, ");
    print_u64(fail as u64);
    print(b" fail ---\n");

    if fail == 0 {
        print(b"STYX TEST: ALL PASS\n");
    } else {
        print(b"STYX TEST: SOME FAILED\n");
    }

    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"STYX TEST: PANIC!\n");
    loop {
        sys::yield_now();
    }
}
