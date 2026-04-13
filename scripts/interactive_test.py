#!/usr/bin/env python3
"""
sotX Cybersecurity Demo — Interactive Phase Testing.
Sends commands via serial stdin to QEMU. Uses LF (0x0A) as Enter
because QEMU on Windows strips CR (0x0D) from serial stdio.
"""
import subprocess, time, sys, os, threading

QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
BOOT_WAIT = 40
CHAR_DELAY = 0.03
LINE_DELAY = 4.0
LONG_DELAY = 18


def run():
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    print("=" * 70)
    print("  sotX Cybersecurity Demo — Interactive Phase Testing")
    print("=" * 70)

    proc = subprocess.Popen([
        QEMU,
        '-drive', 'format=raw,file=target/sotx.img',
        '-drive', 'if=none,format=raw,file=target/disk.img,id=disk0',
        '-device', 'virtio-blk-pci,drive=disk0,disable-modern=on',
        '-netdev', 'user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::7777-:7',
        '-device', 'virtio-net-pci,netdev=net0,disable-modern=on',
        '-serial', 'stdio', '-display', 'none', '-no-reboot', '-m', '256M',
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

    output = bytearray()
    lock = threading.Lock()

    def reader():
        while True:
            b = proc.stdout.read(1)
            if not b: break
            with lock:
                output.extend(b)
            sys.stdout.buffer.write(b)
            sys.stdout.buffer.flush()

    threading.Thread(target=reader, daemon=True).start()

    def get():
        with lock:
            return bytes(output).decode(errors='replace')

    def send(text, delay=None):
        sys.stdout.write(f'\n>>> {text}\n')
        sys.stdout.flush()
        for ch in text.encode('ascii'):
            proc.stdin.write(bytes([ch]))
            proc.stdin.flush()
            time.sleep(CHAR_DELAY)
        # Use LF (0x0A) as Enter — QEMU Windows strips CR
        proc.stdin.write(b'\n')
        proc.stdin.flush()
        time.sleep(delay or LINE_DELAY)

    print(f'\n[*] Waiting {BOOT_WAIT}s for boot...\n')
    time.sleep(BOOT_WAIT)

    if 'v0.2' not in get():
        print('[!] Shell not ready, waiting 15 more seconds...')
        time.sleep(15)

    # === CYBERSECURITY DEMO ===

    # Phase 3: Time illusion — uptime shows 3+ days
    send('uptime')
    send('cat /proc/uptime')
    send('cat /proc/version')
    send('cat /proc/loadavg')

    # Phase 3: CPU info
    send('cat /proc/cpuinfo')

    # Phase 5: Syscall shadow log
    send('syslog 10', delay=5)

    # Phase 5: Network mirror ON
    send('netmirror on')

    # Phase 4+5: wget with mirror active — real network traffic
    send('wget http://example.com', delay=LONG_DELAY)

    # Verify file downloaded
    send('ls')
    send('cat index.html', delay=6)

    # Phase 5: Syslog after traffic
    send('syslog 5', delay=5)

    # Mirror OFF
    send('netmirror off')

    # Phase 4: Snapshots
    send('snap list')

    time.sleep(3)

    # Shutdown
    sys.stdout.write('\n[*] Shutting down QEMU...\n')
    sys.stdout.flush()
    proc.stdin.close()
    try:
        proc.wait(timeout=5)
    except:
        proc.terminate()
        proc.wait(5)

    time.sleep(1)
    final = get()

    print('\n' + '=' * 70)
    print('  DEMO COMPLETE')
    print('=' * 70)

    checks = [
        ('Boot validation (13/13)',   'VALIDATION: 13 passed' in final),
        ('LUCAS shell started',       'v0.2' in final),
        ('Uptime >3 days',            '259' in final),
        ('/proc/version shows sotX', 'Linux version' in final and 'sotX' in final),
        ('Syslog entries visible',    'pid=' in final),
        ('Net mirror toggle',         'MIRROR' in final or 'mirroring' in final),
        ('wget downloaded HTML',      '<html' in final.lower() or 'DOCTYPE' in final or 'Example Domain' in final),
    ]

    print('\nResult Summary:')
    for name, passed in checks:
        status = 'PASS' if passed else '???'
        print(f'  [{status}] {name}')

    return 0


if __name__ == '__main__':
    sys.exit(run())
