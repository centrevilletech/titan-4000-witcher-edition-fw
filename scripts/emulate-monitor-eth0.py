#!/usr/bin/env python3
"""Run the Titan `monitor` eth0 check (0x9bf0) in Unicorn.

The real ARM code of `monitor` and the real uClibc `atoi` -> `strtol` ->
`_stdlib_strto_l_l` run in the emulator. Only I/O is stubbed: popen/fgets
return the counter text we choose, and system()/kill() are recorded, never
executed. Nothing touches the host network or a device.

usage: emulate-monitor-eth0.py ROOTFS [MONITOR] [--real QEMU SYSROOT]

ROOTFS is an extracted stock 4172 root filesystem. MONITOR defaults to its
/usr/sbin/monitor; pass a patched copy to compare. With --real, each popen()
command runs for real: the stock BusyBox grep and awk under qemu-arm (SYSROOT
is a copy of the image's bin/busybox and lib/ with plain files), on a file
standing in for /proc/net/dev that holds the counters of the current pass.

For reviewers; CI does not run it. Needs Python packages unicorn and
pyelftools. See docs/long-runs.md for the results.
"""
import os
import struct
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
                               UC_ARM_REG_C13_C0_3)

ROOT = sys.argv[1]
ARGS = sys.argv[2:]
REAL = None
if '--real' in ARGS:
    i = ARGS.index('--real')
    REAL = (ARGS[i + 1], ARGS[i + 2])
    del ARGS[i:i + 3]
MONITOR = ARGS[0] if ARGS else f'{ROOT}/usr/sbin/monitor'
LIB_BASE = 0x40000000
STACK = 0x7f000000
HEAP = 0x60000000
TLS = 0x61000000
STOP = 0x70000000  # return address that ends a call
KUSER = 0xffff0000

uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
page = lambda n: (n + 0xfff) & ~0xfff


def load(path, base):
    elf = ELFFile(open(path, 'rb'))
    data = open(path, 'rb').read()
    lo = min(s['p_vaddr'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD') & ~0xfff
    hi = max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
    uc.mem_map(base + lo, page(hi - lo + 0x1000))
    for s in elf.iter_segments():
        if s['p_type'] == 'PT_LOAD':
            uc.mem_write(base + s['p_vaddr'], data[s['p_offset']:s['p_offset'] + s['p_filesz']])
    return elf


def symbols(elf):
    out = {}
    for sec in elf.iter_sections():
        if sec.name in ('.dynsym', '.symtab'):
            for sym in sec.iter_symbols():
                if sym['st_shndx'] != 'SHN_UNDEF' and sym.name:
                    out[sym.name] = sym['st_value']
    return out


stubs = {}       # address -> (name, handler)
next_stub = [0x50000000]
uc.mem_map(0x50000000, 0x10000)


def stub_for(name, handler=None):
    for addr, (n, _) in stubs.items():
        if n == name:
            return addr
    addr = next_stub[0]
    next_stub[0] += 4
    uc.mem_write(addr, struct.pack('<I', 0xe12fff1e))  # bx lr
    stubs[addr] = (name, handler)
    return addr


def relocate(elf, base, resolve):
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        symtab = elf.get_section(sec['sh_link'])
        for rel in sec.iter_relocations():
            kind = rel['r_info_type']
            loc = base + rel['r_offset']
            cur = struct.unpack('<I', uc.mem_read(loc, 4))[0]
            sym = symtab.get_symbol(rel['r_info_sym']) if rel['r_info_sym'] else None
            if kind == 23:  # R_ARM_RELATIVE
                val = base + cur
            elif kind in (21, 22, 2):  # GLOB_DAT, JUMP_SLOT, ABS32
                val = resolve(sym.name) + (cur if kind == 2 else 0)
            else:  # TLS offsets: leave as is; TLS points at zeroed scratch
                continue
            uc.mem_write(loc, struct.pack('<I', val & 0xffffffff))


lib = load(f'{ROOT}/lib/libuClibc-0.9.33.2.so', LIB_BASE)
libsyms = symbols(lib)
mon = load(MONITOR, 0)


def lib_or_stub(name):
    if name in libsyms:
        return LIB_BASE + libsyms[name]
    return stub_for(name)


relocate(lib, LIB_BASE, lib_or_stub)

# Stack, heap, TLS, and the kernel user helper page (__kuser_get_tls).
uc.mem_map(STACK - 0x100000, 0x100000)
uc.mem_map(HEAP, 0x100000)
uc.mem_map(TLS, 0x10000)
uc.mem_map(STOP, 0x1000)
uc.mem_map(KUSER, 0x1000)
uc.mem_write(KUSER + 0xfe0, struct.pack('<III', 0xe59f0000, 0xe12fff1e, TLS + 0x8000))  # ldr r0,[pc]; bx lr
uc.reg_write(UC_ARM_REG_C13_C0_3, TLS + 0x8000)

reg = lambda r: uc.reg_read(r)
cstr = lambda a: bytes(uc.mem_read(a, 256)).split(b'\0')[0].decode('latin1')

# --- what the stubbed world returns -------------------------------------------
state = {'answers': [], 'calls': [], 'heap': HEAP}


def popen(_):
    cmd = cstr(reg(UC_ARM_REG_R0))
    state['calls'].append(('popen', cmd))
    state['current'] = cmd
    uc.reg_write(UC_ARM_REG_R0, 0x1234)


WORK = tempfile.mkdtemp(prefix='monitor-e2e-')
if REAL:
    qemu, sysroot = REAL
    os.mkdir(f'{WORK}/bin')
    for applet in ('cat', 'grep', 'awk'):
        with open(f'{WORK}/bin/{applet}', 'w') as f:
            f.write(f'#!/bin/sh\nexec {qemu} -L {sysroot} {sysroot}/bin/busybox {applet} "$@"\n')
        os.chmod(f'{WORK}/bin/{applet}', 0o755)


def run_real(cmd):
    dev = f'{WORK}/net-dev'
    with open(dev, 'w') as f:
        f.write('Inter-|   Receive                                                |  Transmit\n')
        f.write(' face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n')
        f.write('    lo:    1234      12    0    0    0     0          0         0     1234      12    0    0    0     0       0          0\n')
        f.write(f"  eth0: 3460000000 {state['rx'].strip()}    0    0    0     0          0         0 3460000000 {state['tx'].strip()}    0    0    0     0       0          0\n")
    out = subprocess.run(['/bin/sh', '-c', cmd.replace('/proc/net/dev', dev)], capture_output=True, text=True,
                         env=dict(os.environ, PATH=f'{WORK}/bin:/usr/bin:/bin'), timeout=60).stdout
    return out.splitlines()[0] + '\n' if out else None


def fgets(_):
    buf = reg(UC_ARM_REG_R0)
    cmd = state.get('current', '')
    if REAL and 'net/dev' in cmd:
        text = run_real(cmd)
        state['seen'].append(text.strip() if text else None)
        if text is None:
            uc.reg_write(UC_ARM_REG_R0, 0)
            return
        uc.mem_write(buf, text.encode() + b'\0')
        uc.reg_write(UC_ARM_REG_R0, buf)
        return
    if "print $3}'" in cmd and 'net/dev' in cmd:
        text = state['rx']
    elif "print $11}'" in cmd:
        text = state['tx']
    elif 'ifconfig eth0' in cmd:
        text = 'RUNNING\n'
    else:
        uc.reg_write(UC_ARM_REG_R0, 0)
        return
    uc.mem_write(buf, text.encode() + b'\0')
    uc.reg_write(UC_ARM_REG_R0, buf)


def snprintf(_):
    # The formats used here carry no arguments: copy the format string.
    uc.mem_write(reg(UC_ARM_REG_R0), cstr(reg(UC_ARM_REG_R2)).encode() + b'\0')
    uc.reg_write(UC_ARM_REG_R0, 0)


def sprintf(_):
    uc.mem_write(reg(UC_ARM_REG_R0), cstr(reg(UC_ARM_REG_R1)).encode() + b'\0')
    uc.reg_write(UC_ARM_REG_R0, 0)


def record(name, args=1):
    def handler(_):
        vals = [reg(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1)[:args]]
        shown = [cstr(v) if 0x8000 <= v < 0x20000 else v for v in vals]
        state['calls'].append((name, *shown))
        uc.reg_write(UC_ARM_REG_R0, 0)
    return handler


def ret(value, name=None):
    def handler(_):
        if name:
            state['calls'].append((name,))
        uc.reg_write(UC_ARM_REG_R0, value)
    return handler


# A locale whose first field is a ctype table: only the C whitespace bytes
# carry _ISspace (0x20), as in the C locale. The table pointer is at index 0
# with 128 entries before it, because uClibc indexes it with a signed char.
LOCALE = HEAP + 0x4000
CTYPE = HEAP + 0x5000
uc.mem_write(CTYPE - 256, b'\0' * 768)
for ch in b' \t\n\v\f\r':
    uc.mem_write(CTYPE + 2 * ch, struct.pack('<H', 0x20))
uc.mem_write(LOCALE, struct.pack('<I', CTYPE))


def curlocale(_):
    uc.reg_write(UC_ARM_REG_R0, LOCALE)


def uidiv(_):
    n, d = reg(UC_ARM_REG_R0), reg(UC_ARM_REG_R1)
    uc.reg_write(UC_ARM_REG_R0, n // d)


def uidivmod(_):
    n, d = reg(UC_ARM_REG_R0), reg(UC_ARM_REG_R1)
    uc.reg_write(UC_ARM_REG_R0, n // d)
    uc.reg_write(UC_ARM_REG_R1, n % d)


handlers = {
    'popen': popen, 'fgets': fgets, 'pclose': ret(0), 'snprintf': snprintf,
    'sprintf': sprintf, 'system': record('system'), 'sleep': ret(0),
    'cpe_debug_out': ret(0), 'find_pid_by_name': ret(321),
    'kill': record('kill', 2), 'nvram_cache_set': record('nvram_cache_set', 2),
    'nvram_cache_get': ret(0), 'nvram_get': ret(0), 'nvram_set': record('nvram_set', 2),
    '__curlocale': curlocale, '__errno_location': ret(TLS + 0x100),
    '__aeabi_uidiv': uidiv, '__aeabi_uidivmod': uidivmod,
}
# The library's own __curlocale may read TLS through helpers we cannot
# relocate; route it to the global locale.
if '__curlocale' in libsyms:
    stubs[LIB_BASE + libsyms['__curlocale']] = ('__curlocale', curlocale)


for addr, (name, h) in list(stubs.items()):
    if h is None and name in handlers:
        stubs[addr] = (name, handlers[name])
unhandled = sorted(n for n, h in stubs.values() if h is None)


def mon_resolve(name):
    if name in ('atoi', 'strtol', 'strncmp', 'memset', 'strstr', 'strcmp', 'strlen', 'strcpy'):
        return LIB_BASE + libsyms[name]
    return stub_for(name, handlers.get(name))


for addr, (name, _) in list(stubs.items()):
    if name in handlers:
        stubs[addr] = (name, handlers[name])
relocate(mon, 0, mon_resolve)
for addr, (name, h) in list(stubs.items()):
    if h is None and name in handlers:
        stubs[addr] = (name, handlers[name])


def on_code(uc_, address, size, _):
    if address in stubs:
        name, handler = stubs[address]
        if handler is None:
            handler = ret(0)
        handler(None)
        uc_.reg_write(UC_ARM_REG_PC, reg(UC_ARM_REG_LR))
    elif address == STOP:
        uc_.emu_stop()


uc.hook_add(UC_HOOK_CODE, on_code)


def call(addr, *args):
    for r, v in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
        uc.reg_write(r, v)
    uc.reg_write(UC_ARM_REG_SP, STACK - 0x100)
    uc.reg_write(UC_ARM_REG_LR, STOP)
    try:
        uc.emu_start(addr, STOP, count=2_000_000)
    except UcError as err:
        raise SystemExit(f'emulation error at {reg(UC_ARM_REG_PC):#x}: {err}')
    return reg(UC_ARM_REG_R0)


def atoi(text):
    buf = HEAP + 0x8000
    uc.mem_write(buf, text.encode() + b'\0')
    value = call(LIB_BASE + libsyms['atoi'], buf)
    return value - (1 << 32) if value & 0x80000000 else value


print('library imports left as no-op stubs:', ', '.join(unhandled[:40]), '...' if len(unhandled) > 40 else '')
print('uClibc atoi (real ARM code, uClibc 0.9.33.2 from the stock 4172 rootfs):')
for text in ['0', '1153475', '  42', '2147483646', '2147483647', '2147483648', '3000000000', '4294967295', '-5']:
    print(f'  atoi("{text}") = {atoi(text)}')

ETH_CHECK = 0x9bf0
PREV_RX, PREV_TX, STREAK = 0x14b74, 0x14b70, 0x14b6c
read32 = lambda a: struct.unpack('<i', uc.mem_read(a, 4))[0]


def tick(rx, tx):
    state['rx'], state['tx'] = f'{rx}\n', f'{tx}\n'
    state['calls'] = []
    state['seen'] = []
    call(ETH_CHECK)
    acts = [c for c in state['calls'] if c[0] != 'popen']
    return acts


def scenario(title, start_rx, start_tx, rx_per_tick, tx_per_tick, ticks):
    print(f'\n{title}')
    for addr in (PREV_RX, PREV_TX, STREAK):
        uc.mem_write(addr, b'\0' * 4)
    rx, tx = start_rx, start_tx
    for n in range(ticks):
        acts = tick(rx % (1 << 32), tx % (1 << 32))
        shown = '; '.join(' '.join(str(x) for x in a) for a in acts) or 'nothing'
        seen = f" awk printed {state['seen']}" if REAL else ''
        print(f'  tick {n + 1} (+{(n + 1) * 2} min) rx={rx % (1 << 32):>10} tx={tx % (1 << 32):>10}{seen}'
              f' prev=({read32(PREV_RX)},{read32(PREV_TX)}) streak={read32(STREAK)}: {shown}')
        rx += rx_per_tick
        tx += tx_per_tick


# A busy line: both counters move every 2 minutes.
scenario('Both counters below 2^31 and moving:', 2_000_000_123, 1_000_000_456, 60_000, 30_000, 4)
scenario('Both counters past 2^31 - 1 and still moving (traffic flowing):',
         2_147_400_000, 2_147_450_000, 60_000, 30_000, 7)
scenario('Only rx past 2^31 - 1 (tx still below):', 2_200_000_123, 1_000_000_456, 60_000, 30_000, 4)
scenario('Both counters near the 32-bit wrap, still moving:', 4_294_900_000, 4_294_930_000, 60_000, 30_000, 4)
scenario('A real freeze: no frame either way, both counters past 2^31:', 3_000_000_000, 2_500_000_000, 0, 0, 4)
scenario('A real freeze with small counters:', 1_153_475, 239_908, 0, 0, 4)
print('monitor binary:', MONITOR)
