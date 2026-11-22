#!/usr/bin/env python3
"""Run the PDN-change and carrier-change code of the vendor rcinit and ucid.

Unicorn (the QEMU CPU emulator as a library) runs the real ARM code of each
handler from its entry point: rcinit's signal handler (0xd1d8), stop_l2tp
(0x3aa8c) and stop_udhcpd (0x12884), and ucid's PDN handler (0x240b0) and
handover handler (0xdef4). Library imports (libc, nvram, sleep, system, kill)
are answered in Python and recorded. A call into another rcinit or ucid
function that is not on the path under test is recorded and returns 0. No
command runs, nothing touches the host network, and no device is involved.

ucid's radio poll loop talks to a simulated modem: after ucid sets
sqns_admin_refresh=1, the modem writes a fresh radio report LAG seconds of
emulated sleep() later. A request made while a read is in flight joins it. The scenarios print an event trace and the emulated
time at which ucid signals rcinit.

usage: emulate-pdn-paths.py ROOTFS [--expect stock|patched] [--rcinit FILE] [--ucid FILE]

ROOTFS holds usr/sbin/rcinit and usr/sbin/ucid (an extracted image).
--rcinit/--ucid override either file. --expect checks the trace against the
stock 4172 code or the Witcher patches (scripts/patch-rcinit.py,
scripts/patch-ucid.py) and exits non-zero on any difference. Needs the Python
packages unicorn and pyelftools.
"""
import argparse
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)

ARGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
STUBS, HEAP, STACK_TOP, STOP = 0x60000000, 0x61000000, 0x7f000000, 0x70000000
PAGE = 0x1000


def cformat(fmt, next_arg, read_str):
    """Enough of C printf for the vendor format strings."""
    out, i = [], 0
    while i < len(fmt):
        c = fmt[i]
        if c != '%':
            out.append(c)
            i += 1
            continue
        j = i + 1
        while j < len(fmt) and fmt[j] in '-+ #0123456789.lhz':
            j += 1
        spec, conv = fmt[i + 1:j].replace('l', '').replace('h', '').replace('z', ''), fmt[j]
        i = j + 1
        if conv == '%':
            out.append('%')
            continue
        value = next_arg()
        if conv == 's':
            out.append(('%' + spec + 's') % (read_str(value) if value else '(null)'))
        elif conv in 'di':
            out.append(('%' + spec + 'd') % (value - (1 << 32) if value & 0x80000000 else value))
        elif conv in 'uxXc':
            out.append(('%' + spec + conv) % value)
        elif conv == 'p':
            out.append(f'0x{value:x}')
        else:
            out.append('%' + spec + conv)
    return ''.join(out)


class Emulator:
    """One ARM executable in Unicorn with Python imports and recorded internal calls."""

    def __init__(self, path, real):
        self.path, self.real = Path(path), set(real)
        data = self.path.read_bytes()
        elf = ELFFile(open(path, 'rb'))
        self.uc = uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        lo = min(s['p_vaddr'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD') & ~(PAGE - 1)
        hi = max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
        uc.mem_map(lo, (hi - lo + 2 * PAGE) & ~(PAGE - 1))
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                uc.mem_write(seg['p_vaddr'], data[seg['p_offset']:seg['p_offset'] + seg['p_filesz']])
        text = elf.get_section_by_name('.text')
        self.text = (text['sh_addr'], text['sh_addr'] + text['sh_size'])
        # Every unconditional `bl` in .text: internal calls outside `real` are skipped and recorded.
        self.bl = {}
        start = text['sh_offset']
        for off in range(0, text['sh_size'], 4):
            word = struct.unpack_from('<I', data, start + off)[0]
            if word >> 24 == 0xeb:
                imm = word & 0xffffff
                imm = imm - (1 << 24) if imm & 0x800000 else imm
                site = self.text[0] + off
                target = site + 8 + imm * 4
                if self.text[0] <= target < self.text[1]:
                    self.bl[site] = target
        uc.mem_map(STUBS, 0x10000)
        uc.mem_map(HEAP, 0x100000)
        uc.mem_map(STACK_TOP - 0x100000, 0x100000)
        uc.mem_map(STOP, PAGE)
        self.stub_names, self.handlers, self.returns, self.names = {}, {}, {}, {}
        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection):
                symtab = elf.get_section(sec['sh_link'])
                for rel in sec.iter_relocations():
                    if rel['r_info_type'] == 22:  # R_ARM_JUMP_SLOT
                        name = symtab.get_symbol(rel['r_info_sym']).name
                        stub = STUBS + 4 * len(self.stub_names)
                        uc.mem_write(stub, struct.pack('<I', 0xe12fff1e))  # bx lr
                        self.stub_names[stub] = name
                        uc.mem_write(rel['r_offset'], struct.pack('<I', stub))
        self.heap = HEAP
        self.nvram, self.nvram_ptr = {}, {}
        self.events, self.clock, self.pids = [], 0, {}
        self.on_sleep = None
        uc.hook_add(UC_HOOK_CODE, self._hook)

    # --- memory helpers ---------------------------------------------------
    def reg(self, r):
        return self.uc.reg_read(r)

    def u32(self, addr):
        return struct.unpack('<I', self.uc.mem_read(addr, 4))[0]

    def put32(self, addr, value):
        self.uc.mem_write(addr, struct.pack('<I', value & 0xffffffff))

    def cstr(self, addr, limit=512):
        raw = bytes(self.uc.mem_read(addr, limit))
        return raw.split(b'\0')[0].decode('latin1')

    def alloc_str(self, text):
        addr = self.heap
        raw = text.encode('latin1') + b'\0'
        self.uc.mem_write(addr, raw)
        self.heap += (len(raw) + 7) & ~7
        return addr

    def set_nvram(self, key, value):
        self.nvram[key] = value
        self.nvram_ptr.pop(key, None)

    # --- variadic arguments ---------------------------------------------
    def varargs(self, first):
        """Iterator over variadic arguments that start at argument register `first`."""
        state = {'n': first}

        def next_arg():
            n = state['n']
            state['n'] += 1
            if n < 4:
                return self.reg(ARGS[n])
            return self.u32(self.reg(UC_ARM_REG_SP) + 4 * (n - 4))
        return next_arg

    def va_list(self, pointer):
        state = {'p': pointer}

        def next_arg():
            value = self.u32(state['p'])
            state['p'] += 4
            return value
        return next_arg

    # --- import handlers ----------------------------------------------------
    def _import(self, name):
        r = [self.reg(a) for a in ARGS]
        record = self.events.append
        fmt = lambda f, nxt: cformat(self.cstr(f), nxt, self.cstr)
        if name == 'nvram_cache_get':
            key = self.cstr(r[0])
            if key not in self.nvram:
                return 0
            if key not in self.nvram_ptr:
                self.nvram_ptr[key] = self.alloc_str(self.nvram[key])
            return self.nvram_ptr[key]
        if name == 'nvram_cache_set':
            key, value = self.cstr(r[0]), self.cstr(r[1])
            self.set_nvram(key, value)
            record(('set', key, value))
            if self.on_set:
                self.on_set(key, value)
            return 0
        if name in ('sprintf', 'vsprintf', 'snprintf'):
            if name == 'snprintf':
                text = fmt(r[2], self.varargs(3))[:max(r[1] - 1, 0)]
            elif name == 'sprintf':
                text = fmt(r[1], self.varargs(2))
            else:
                text = fmt(r[1], self.va_list(r[2]))
            self.uc.mem_write(r[0], text.encode('latin1') + b'\0')
            return len(text)
        if name == 'sysprintf':
            record(('sh', fmt(r[0], self.varargs(1))))
            return 0
        if name == 'system':
            record(('sh', self.cstr(r[0])))
            return 0
        if name == 'cpe_debug_out':
            record(('log', self.cstr(r[3]).strip()))
            return 0
        if name == 'sdk_log':
            record(('log', fmt(r[1], self.varargs(2)).strip()))
            return 0
        if name == 'sleep':
            record(('sleep', r[0]))
            self.clock += r[0]
            if self.on_sleep:
                self.on_sleep()
            return 0
        if name == 'usleep':
            record(('usleep', r[0]))
            self.clock += r[0] / 1e6
            if self.on_sleep:
                self.on_sleep()
            return 0
        if name == 'find_pid_by_name':
            found = self.pids.get(self.cstr(r[0]), 0)
            return found() if callable(found) else found
        if name in ('kill', 'killall'):
            target = r[0] if name == 'kill' else self.cstr(r[0])
            record((name, target, r[1]))
            if name == 'killall' and self.on_kill:
                self.on_kill(target, r[1])
            return 0
        if name == 'sysinfo':
            self.uc.mem_write(r[0], struct.pack('<I', int(self.clock) + 1000) + b'\0' * 60)
            return 0
        if name == 'strcmp' or name == 'strncmp':
            a, b = self.cstr(r[0]), self.cstr(r[1])
            if name == 'strncmp':
                a, b = a[:r[2]], b[:r[2]]
            return 0 if a == b else (1 if a > b else 0xffffffff)
        if name == 'strlen':
            return len(self.cstr(r[0], 4096))
        if name in ('strcpy', 'strncpy'):
            text = self.cstr(r[1], 4096)
            if name == 'strncpy':
                raw = text.encode('latin1')[:r[2]].ljust(r[2], b'\0')
            else:
                raw = text.encode('latin1') + b'\0'
            self.uc.mem_write(r[0], raw)
            return r[0]
        if name == 'strstr':
            hay, needle = self.cstr(r[0], 4096), self.cstr(r[1])
            at = hay.find(needle)
            return 0 if at < 0 else r[0] + at
        if name == 'memset':
            self.uc.mem_write(r[0], bytes([r[1] & 0xff]) * r[2])
            return r[0]
        if name == 'memcpy':
            self.uc.mem_write(r[0], bytes(self.uc.mem_read(r[1], r[2])))
            return r[0]
        if name == 'atoi':
            text = self.cstr(r[0]).strip()
            digits = ''
            for ch in text:
                if ch.isdigit() or (not digits and ch in '+-'):
                    digits += ch
                else:
                    break
            try:
                return int(digits) & 0xffffffff
            except ValueError:
                return 0
        if name == 'check_wan_link':
            return 1
        if name in ('route_del', 'unlink'):
            record((name, self.cstr(r[0]) if name == 'unlink' else 'route'))
            return 0
        if name in ('pthread_mutex_lock', 'pthread_mutex_unlock', 'Nvram_CommitEX'):
            return 0
        record(('import', name))
        return 0

    on_set = None
    on_kill = None

    def _hook(self, uc, address, size, _):
        if address in self.stub_names:
            uc.reg_write(UC_ARM_REG_R0, self._import(self.stub_names[address]) & 0xffffffff)
            uc.reg_write(UC_ARM_REG_PC, self.reg(UC_ARM_REG_LR))
        elif address in self.bl and self.bl[address] not in self.real:
            target = self.bl[address]
            self.events.append(('call', self.names.get(target, f'0x{target:x}'), self.reg(UC_ARM_REG_R0)))
            uc.reg_write(UC_ARM_REG_R0, self.returns.get(target, 0))
            uc.reg_write(UC_ARM_REG_PC, address + 4)
        elif address == STOP:
            uc.emu_stop()

    def call(self, entry, *args):
        for reg, value in zip(ARGS, args):
            self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM_REG_SP, STACK_TOP - 0x1000)
        self.uc.reg_write(UC_ARM_REG_LR, STOP)
        try:
            self.uc.emu_start(entry, STOP, count=5_000_000)
        except UcError as error:
            raise SystemExit(f'{self.path.name}: emulation error at 0x{self.reg(UC_ARM_REG_PC):x}: {error}')
        if self.reg(UC_ARM_REG_PC) != STOP:
            raise SystemExit(f'{self.path.name}: did not return from 0x{entry:x} (pc 0x{self.reg(UC_ARM_REG_PC):x})')
        return self.reg(UC_ARM_REG_R0)


# --- rcinit -----------------------------------------------------------------
RCINIT_NAMES = {
    0x2180c: 'stop_wan', 0x1add8: 'stop_lan', 0x1a7b0: 'start_bridge_lan', 0x1bac4: 'start_wan',
    0x1d4d4: 'start_pdn(boot)', 0x142b8: 'stop_upnp', 0x13de0: 'start_upnp', 0x15484: 'cbrs_lte_change',
    0x30cbc: 'restart_firewall(NAT)', 0x1c1d8: 'start_bridge_firewall', 0x30f28: 'stop_ipv6_firewall',
    0x30d0c: 'start_ipv6_firewall', 0x3355c: 'upgrade_notify',
}
RCINIT_REAL = {0xd1d8, 0xcc1c, 0xcc4c, 0xcc74, 0xcc9c, 0xccf8, 0x3aa8c, 0x3b3f4, 0x12884, 0xf218}
BOOT_FLAG, UPGRADE_FLAG = 0x503cc, 0x503d0


def rcinit_run(path, nvram, boot=0, entry=0xd1d8, pids=None, on_kill=None):
    emu = Emulator(path, RCINIT_REAL)
    emu.names = RCINIT_NAMES
    base = {'router_disable': '1', 'sqns_radio_band': '48', 'sqns_connection_mediaState': 'ATTACHED',
            'sqns_network_changed': '0', 'sqns_network_ra': '0', 'sqns_network_cbrs': '0',
            'wan_ipaddr': '192.0.2.10', 'ip_proto': '0'}
    base.update(nvram)
    for key, value in base.items():
        emu.set_nvram(key, value)
    emu.put32(BOOT_FLAG, boot)
    emu.put32(UPGRADE_FLAG, boot)
    emu.pids = pids or {}
    emu.on_kill = on_kill
    emu.call(entry)
    return emu


def rcinit_scenarios(path):
    out = {}
    out['A pdn change, passthrough'] = rcinit_run(path, {'sqns_network_changed': '1'})
    out['A2 pdn change, first event after an rcinit start'] = rcinit_run(path, {'sqns_network_changed': '1'}, boot=1)
    out['A3 pdn change, NAT mode'] = rcinit_run(path, {'sqns_network_changed': '1', 'router_disable': '0'})
    out['B carrier change, passthrough'] = rcinit_run(path, {'sqns_network_cbrs': '1'})
    out['B2 carrier change, NAT mode'] = rcinit_run(path, {'sqns_network_cbrs': '1', 'router_disable': '0'})
    out['C IPv6 RA'] = rcinit_run(path, {'sqns_network_ra': '1'})
    out['D stop_l2tp, nothing running'] = rcinit_run(path, {}, entry=0x3aa8c)
    alive = {'pppd': 4}

    def pppd_pid():
        alive['pppd'] -= 1 if alive['pppd'] < 4 else 0
        return 321 if alive['pppd'] > 0 else 0

    def pppd_term(name, sig):
        if name == 'pppd' and alive['pppd'] == 4:
            alive['pppd'] = 3  # exits about 0.3 s after SIGTERM
    out['D2 stop_l2tp, pppd running'] = rcinit_run(path, {}, entry=0x3aa8c, pids={'pppd': pppd_pid},
                                                    on_kill=pppd_term)
    out['E stop_udhcpd'] = rcinit_run(path, {}, entry=0x12884)
    return out


# --- ucid -------------------------------------------------------------------
UCID_REAL = {0x240b0, 0xdef4, 0xfe30, 0xfe98, 0xff04, 0xffa4, 0xfff8, 0xf228, 0xf284, 0x1004c}
ATTACHED, CBRS_PDN, SIGNAL_ON, PDNS_BUF, HANDOVER_FLAG, HANDOVER_TIME = \
    0x5966c, 0x59a4c, 0x51ce4, 0x5c9c4, 0x598d9, 0x59a04
FRESH = {'sqns_radio_band': '48', 'sqns_radio_freqDl': '3640000', 'sqns_radio_bandwidthDl': '20000',
         'sqns_radio_earfcnDl': '56240', 'sqns_radio_pci': '11'}
STALE = {'sqns_radio_band': '48', 'sqns_radio_freqDl': '3580000', 'sqns_radio_bandwidthDl': '20000',
         'sqns_radio_earfcnDl': '55640', 'sqns_radio_pci': '22'}


def ucid_emulator(path):
    emu = Emulator(path, UCID_REAL)
    emu.names = {0x14b34: 'pdn_busy_check', 0x21f38: 'pdn_setup', 0x22724: 'pdn_down'}
    emu.set_nvram('rc_signal_done', '1')
    emu.set_nvram('sqns_connection_powerOnSet', 'ON')
    emu.pids = {'rcinit': 123}
    return emu


def ucid_pdn_up(path, lag, before, answers=True):
    """PDN up with a modem that answers each refresh request after `lag` s of sleep()."""
    emu = ucid_emulator(path)
    for key, value in before.items():
        emu.set_nvram(key, value)
    emu.put32(ATTACHED, 1)
    emu.put32(CBRS_PDN, 1)
    emu.put32(SIGNAL_ON, 1)
    emu.uc.mem_write(PDNS_BUF, b'mgmt,198.51.100.2#data,192.0.2.10#\0')
    pending = []

    def on_set(key, value):
        # One read at a time: a refresh request while a read is in flight joins it.
        if key == 'sqns_admin_refresh' and value == '1' and answers and not pending:
            pending.append(emu.clock + lag)
    emu.on_set = on_set

    def on_sleep():
        while pending and pending[0] <= emu.clock:
            pending.pop(0)
            for key, value in FRESH.items():
                emu.set_nvram(key, value)
            emu.events.append(('modem', f'report t={emu.clock:g}'))
    emu.on_sleep = on_sleep
    state = HEAP + 0xff000
    emu.call(0x240b0, 0, state)
    emu.signal_time = next((t for t, e in timeline(emu) if e[:2] == ('kill', 123)), None)
    return emu


def timeline(emu):
    t, out = 0, []
    for e in emu.events:
        if e[0] == 'sleep':
            t += e[1]
        elif e[0] == 'usleep':
            t += e[1] / 1e6
        out.append((t, e))
    return out


def ucid_handover(path):
    emu = ucid_emulator(path)
    emu.put32(ATTACHED, 1)
    emu.put32(HANDOVER_TIME, 900)  # sysinfo() reports 1000 s: more than 60 s since the change
    emu.uc.mem_write(HANDOVER_FLAG, b'\1')
    for key, value in FRESH.items():
        emu.set_nvram(key, value)
    emu.call(0xdef4)
    return emu


def ucid_scenarios(path):
    return {
        'G1 pdn up, modem answers 1 s after each refresh': ucid_pdn_up(path, 1, {}),
        'G2 pdn up, stale carrier in nvram, modem answers after 3 s': ucid_pdn_up(path, 3, STALE),
        'G3 pdn up, modem never answers': ucid_pdn_up(path, 1, {}, answers=False),
        'H handover (carrier change while attached)': ucid_handover(path),
    }


# --- checks -----------------------------------------------------------------
def count(emu, kind, *match):
    return sum(1 for e in emu.events if e[0] == kind and e[1:1 + len(match)] == match)


def has(emu, kind, *match):
    return count(emu, kind, *match) > 0


def sleeps(emu):
    return [e[1] for e in emu.events if e[0] == 'sleep']


def logs(emu):
    return [e[1] for e in emu.events if e[0] == 'log']


def wipes(emu):
    return count(emu, 'set', 'sqns_radio_freqDl', '-')


def cbrs_line(emu):
    return next((line for line in logs(emu) if line.startswith('*******CBRS(')), None)


def check(results, patched):
    fails = []

    def want(name, ok, detail=''):
        print(f'  {"PASS" if ok else "FAIL"}  {name}{": " + detail if detail and not ok else ""}')
        if not ok:
            fails.append(name)

    bounce = lambda e: (has(e, 'sh', 'ifconfig eth0 down'), has(e, 'sh', 'ifconfig eth0 up'), 2 in sleeps(e))
    for key in ('A pdn change, passthrough', 'A2 pdn change, first event after an rcinit start',
                'A3 pdn change, NAT mode'):
        e = results[key]
        want(f'{key}: eth0 bounce {"gone" if patched else "present"}',
             bounce(e) == ((False,) * 3 if patched else (True,) * 3), str(bounce(e)))
        want(f'{key}: no other sleep', sleeps(e) == ([] if patched else [2]), str(sleeps(e)))
        want(f'{key}: cbrs_lte_change(1) still runs', has(e, 'call', 'cbrs_lte_change', 1))
        want(f'{key}: sqns_network_changed cleared', has(e, 'set', 'sqns_network_changed', '0'))
        tell = 'Witcher keeps eth0 up' if patched else 'down eth0 and sleep 2 sec'
        want(f'{key}: log line', any(tell in line for line in logs(e)), str(logs(e)))
    e = results['A pdn change, passthrough']
    want('A: passthrough runs stop_wan, stop_lan, start_bridge_lan, start_wan in order',
         [x[1] for x in e.events if x[0] == 'call'][:4] == ['stop_wan', 'stop_lan', 'start_bridge_lan', 'start_wan'])
    want('A2: first event after a start takes the boot path', has(results['A2 pdn change, first event after an rcinit start'],
                                                                   'call', 'start_pdn(boot)'))
    for key in ('B carrier change, passthrough', 'B2 carrier change, NAT mode'):
        e = results[key]
        want(f'{key}: NAT-router firewall restart {"skipped" if patched else "called"}',
             has(e, 'call', 'restart_firewall(NAT)') != patched)
        want(f'{key}: cbrs_lte_change(1) still runs', has(e, 'call', 'cbrs_lte_change', 1))
        want(f'{key}: sqns_network_cbrs cleared', has(e, 'set', 'sqns_network_cbrs', '0'))
    e = results['C IPv6 RA']
    want(f'C: sleep before the RA handler {"gone" if patched else "present"}', sleeps(e) == ([] if patched else [1]),
         str(sleeps(e)))
    want('C: RA handler still runs', any('IPV6 RA signal received' in line for line in logs(e)))
    want('C: passthrough bridge firewall still rebuilt', has(e, 'call', 'start_bridge_firewall'))
    for key in ('D stop_l2tp, nothing running', 'D2 stop_l2tp, pppd running'):
        e = results[key]
        want(f'{key}: fixed sleep(2) {"gone" if patched else "present"}', sleeps(e) == ([] if patched else [2]),
             str(sleeps(e)))
        want(f'{key}: still ends with stop_l2tp done', any('stop_l2tp done' in line for line in logs(e)))
    e = results['D2 stop_l2tp, pppd running']
    want('D2: kill helper sends SIGTERM and waits for pppd itself',
         has(e, 'killall', 'pppd', 15) and count(e, 'usleep') >= 1, str(e.events))
    e = results['E stop_udhcpd']
    want('E: both killall commands still run',
         has(e, 'sh', 'killall -10 udhcpd') and has(e, 'sh', 'killall -q udhcpd'))
    want(f'E: sleep(1) between them {"gone" if patched else "present"}', sleeps(e) == ([] if patched else [1]),
         str(sleeps(e)))

    g1, g2, g3 = (results[k] for k in ('G1 pdn up, modem answers 1 s after each refresh',
                                         'G2 pdn up, stale carrier in nvram, modem answers after 3 s',
                                         'G3 pdn up, modem never answers'))
    for name, e, lag in (('G1', g1, 1), ('G2', g2, 3)):
        want(f'{name}: first frequency wipe kept', e.events.index(('set', 'sqns_radio_freqDl', '-')) <
             next(i for i, x in enumerate(e.events) if x[0] == 'modem'))
        want(f'{name}: {"one wipe" if patched else "two wipes"}', wipes(e) == (1 if patched else 2), str(wipes(e)))
        line = cbrs_line(e)
        want(f'{name}: rcinit gets the fresh carrier', line is not None and 'Freq:3640000' in line and
             'Earfcn:56240' in line, str(line))
        # Stock: report, second wipe, report, one more matching read, then sleep(1).
        stock_time = 2 * lag + 2
        want(f'{name}: signal after {lag if patched else stock_time} s of sleep',
             e.signal_time == (lag if patched else stock_time), str(e.signal_time))
        want(f'{name}: sqns_network_changed=1 before the signal', has(e, 'set', 'sqns_network_changed', '1'))
    want('G2: the stale carrier never reaches the CBRS line', 'Freq:3580000' not in (cbrs_line(g2) or ''))
    want('G3: times out after 30 rounds with the vendor exception line',
         any('Exception:(freqDl and bandwidthDl)' in line for line in logs(g3)) and
         sleeps(g3).count(1) == (30 if patched else 31), str(len(sleeps(g3))))
    want('G3: still signals rcinit', has(g3, 'kill', 123, 10))
    h = results['H handover (carrier change while attached)']
    want('H: sqns_network_cbrs=1 then signal', has(h, 'set', 'sqns_network_cbrs', '1') and has(h, 'kill', 123, 10))
    want(f'H: sleep(1) before the signal {"gone" if patched else "present"}', sleeps(h) == ([] if patched else [1]),
         str(sleeps(h)))
    return fails


def show(results):
    for name, emu in results.items():
        print(f'\n{name}  [{emu.path.name}]')
        for t, e in timeline(emu):
            if e[0] in ('set',) and e[1].startswith(('sqns_radio_', 'cbrs_mode', 'sqns_connection_time',
                                                      'sqns_connection_mediaState', 'sqns_network_desc',
                                                      'sqns_network_pdns')) and e[2] != '-':
                continue
            if e[0] == 'log' and not e[1]:
                continue
            print(f'  t={t:<5g} ' + ' '.join(str(x) for x in e))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('--rcinit', type=Path)
    parser.add_argument('--ucid', type=Path)
    parser.add_argument('--expect', choices=('stock', 'patched'))
    parser.add_argument('--quiet', action='store_true', help='print only the checks')
    args = parser.parse_args()
    rcinit = args.rcinit or args.rootfs / 'usr/sbin/rcinit'
    ucid = args.ucid or args.rootfs / 'usr/sbin/ucid'
    results = {**rcinit_scenarios(rcinit), **ucid_scenarios(ucid)}
    if not args.quiet:
        show(results)
    if args.expect:
        print(f'\nchecks against the {args.expect} code:')
        fails = check(results, args.expect == 'patched')
        print('RESULT:', 'ALL PASS' if not fails else f'{len(fails)} FAILURES')
        sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
