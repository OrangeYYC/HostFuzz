import os
import socket
import struct
import threading
import time
from collections import deque

from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2

_SOCK = None
_LOCK = threading.Lock()
_PENDING_EVENTS = deque()
_TRACE_PATH = os.getenv("VIRTBLE_FUZZWARE_HOOK_TRACE", "")
_SEND_COUNT = 0
_RECV_COUNT = 0
_BLOCK_COUNT = 0
_ENTROPY_COUNTER = 0
_BLOCK_LIMIT = int(os.getenv("VIRTBLE_FUZZWARE_BLOCK_LIMIT", "64"))
_ENABLE_BLOCK_TRACE = os.getenv("VIRTBLE_FUZZWARE_ENABLE_BLOCK_TRACE", "0") == "1"
_ENABLE_MAIN_BLOCK_TRACE = os.getenv("VIRTBLE_FUZZWARE_MAIN_BLOCK_TRACE", "0") == "1"
_BT_RECV_PRIO_ADDR = 0x0000DFE1
_BT_HCI_RECV_ADDR = 0x00004815
_HCI_CMD_CONTINUE_ADDR = 0x0000E060


def _trace(msg):
    if not _TRACE_PATH:
        return
    try:
        with open(_TRACE_PATH, "a", encoding="utf-8") as fp:
            fp.write(msg + "\n")
    except OSError:
        pass


_trace("[fuzzware_hooks_11] module loaded")


def _block_probe(uc, address, size=0, user_data=None):
    global _BLOCK_COUNT
    if _ENABLE_MAIN_BLOCK_TRACE and 0x00000A80 <= address <= 0x00000B80:
        _trace(f"MAIN_BLOCK addr=0x{address:08x} size={size}")
    if _BLOCK_COUNT >= _BLOCK_LIMIT:
        return
    _BLOCK_COUNT += 1
    _trace(f"BLOCK#{_BLOCK_COUNT} addr=0x{address:08x} size={size}")


if _ENABLE_BLOCK_TRACE:
    try:
        from fuzzware_harness.user_hooks import add_block_hook

        add_block_hook(_block_probe)
        _trace("[fuzzware_hooks_11] block probe registered")
    except Exception:
        pass


def _u16(uc, addr):
    return struct.unpack("<H", uc.mem_read(addr, 2))[0]


def _u32(uc, addr):
    return struct.unpack("<I", uc.mem_read(addr, 4))[0]


def _w16(uc, addr, value):
    uc.mem_write(addr, struct.pack("<H", value & 0xFFFF))


def _parse_addr(spec, default):
    host, port = (spec or default).rsplit(":", 1)
    return host, int(port)


def _get_timeout_sec():
    timeout_ms = int(os.getenv("VIRTBLE_FUZZWARE_UDP_TIMEOUT_MS", "80"))
    if timeout_ms <= 0:
        timeout_ms = 1
    return timeout_ms / 1000.0


def _ensure_socket():
    global _SOCK
    if _SOCK is not None:
        return _SOCK

    bind_host, bind_port = _parse_addr(
        os.getenv("VIRTBLE_FUZZWARE_UDP_BIND"),
        "127.0.0.1:6667",
    )
    remote_host, remote_port = _parse_addr(
        os.getenv("VIRTBLE_FUZZWARE_UDP_REMOTE"),
        "127.0.0.1:6666",
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    sock.connect((remote_host, remote_port))
    sock.settimeout(_get_timeout_sec())

    _SOCK = sock
    return _SOCK


def _collect_controller_phase(sock):
    packets = []
    deadline = time.monotonic() + _get_timeout_sec()

    while True:
        remain = deadline - time.monotonic()
        if remain <= 0:
            break
        sock.settimeout(remain)
        try:
            data = sock.recv(2048)
        except socket.timeout:
            break
        if len(data) == 1 and data[0] == 0xFF:
            break
        if data:
            packets.append(data)
    return packets


def hci_driver_send_bridge(uc):
    global _SEND_COUNT
    _SEND_COUNT += 1
    pc = uc.reg_read(UC_ARM_REG_PC)
    buf = uc.reg_read(UC_ARM_REG_R1)
    data_ptr = _u32(uc, buf + 12)
    data_len = _u16(uc, buf + 16)
    data_size = _u16(uc, buf + 18)
    _trace(
        f"SEND#{_SEND_COUNT} pc=0x{pc:08x} buf=0x{buf:08x} data_ptr=0x{data_ptr:08x} len={data_len}"
    )
    if data_len == 0 or data_size == 0:
        return

    cmd_len = min(data_len, data_size, 260)
    cmd = bytes(uc.mem_read(data_ptr, cmd_len))
    responses = []
    try:
        sock = _ensure_socket()
        sock.send(cmd)
        responses = _collect_controller_phase(sock)
    except OSError as err:
        print(f"[fuzzware_hooks_11] hci_driver_send_bridge socket error: {err}")

    dispatched = False
    first_event_len = 0
    if responses and data_ptr and data_size:
        first = responses[0]
        first_event_len = min(len(first), data_size)
        if first_event_len > 0:
            uc.mem_write(data_ptr, first[:first_event_len])
            _w16(uc, buf + 16, first_event_len)
            uc.reg_write(UC_ARM_REG_R0, uc.reg_read(UC_ARM_REG_R0))
            uc.reg_write(UC_ARM_REG_R1, buf)
            uc.reg_write(UC_ARM_REG_PC, _BT_HCI_RECV_ADDR)
            dispatched = True

    with _LOCK:
        if dispatched:
            _PENDING_EVENTS.extend(responses[1:])
        else:
            _PENDING_EVENTS.extend(responses)
        pending_cnt = len(_PENDING_EVENTS)
    _trace(
        f"SEND#{_SEND_COUNT} rsp={len(responses)} pending={pending_cnt} dispatched={int(dispatched)} evt_len={first_event_len} cmd_head={cmd[:8].hex()}"
    )

    if responses:
        print(
            f"[fuzzware_hooks_11] send pc=0x{pc:08x} cmd={cmd[:8].hex()} rsp0={responses[0][:12].hex()}",
            flush=False,
        )


def hci_cmd_callsite_bridge(uc):
    global _SEND_COUNT
    _SEND_COUNT += 1

    pc = uc.reg_read(UC_ARM_REG_PC)
    buf = uc.reg_read(UC_ARM_REG_R0)
    evt_ptr_ptr = uc.reg_read(UC_ARM_REG_R1)
    data_ptr = _u32(uc, buf + 12)
    data_len = _u16(uc, buf + 16)
    data_size = _u16(uc, buf + 18)
    _trace(
        f"CALLSITE#{_SEND_COUNT} pc=0x{pc:08x} buf=0x{buf:08x} evt_ptr_ptr=0x{evt_ptr_ptr:08x} data_ptr=0x{data_ptr:08x} len={data_len}"
    )

    if evt_ptr_ptr:
        try:
            uc.mem_write(evt_ptr_ptr, struct.pack("<I", 0))
        except Exception:
            pass

    if data_ptr == 0 or data_len == 0 or data_size == 0:
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, _HCI_CMD_CONTINUE_ADDR)
        return

    cmd_len = min(data_len, data_size, 260)
    cmd_body = bytes(uc.mem_read(data_ptr, cmd_len))
    cmd = b"\x01" + cmd_body
    responses = []
    try:
        sock = _ensure_socket()
        sock.send(cmd)
        responses = _collect_controller_phase(sock)
    except OSError as err:
        print(f"[fuzzware_hooks_11] hci_cmd_callsite_bridge socket error: {err}")

    with _LOCK:
        if len(responses) > 1:
            _PENDING_EVENTS.extend(responses[1:])
        pending_cnt = len(_PENDING_EVENTS)

    if not responses:
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, _HCI_CMD_CONTINUE_ADDR)
        _trace(f"CALLSITE#{_SEND_COUNT} rsp=0 cmd_head={cmd[:8].hex()}")
        return

    event = responses[0]
    event_len = min(len(event), data_size)
    if event_len == 0:
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, _HCI_CMD_CONTINUE_ADDR)
        return

    uc.mem_write(data_ptr, event[:event_len])
    _w16(uc, buf + 16, event_len)
    uc.reg_write(UC_ARM_REG_R0, buf)
    uc.reg_write(UC_ARM_REG_PC, _HCI_CMD_CONTINUE_ADDR)
    _trace(
        f"CALLSITE#{_SEND_COUNT} rsp={len(responses)} evt_len={event_len} pending={pending_cnt} cmd_head={cmd[:8].hex()} evt_head={event[:8].hex()}"
    )
    print(
        f"[fuzzware_hooks_11] callsite pc=0x{pc:08x} cmd={cmd[:8].hex()} rsp0={event[:12].hex()}",
        flush=False,
    )


def bt_hci_recv_bridge(uc):
    global _RECV_COUNT
    _RECV_COUNT += 1
    pc = uc.reg_read(UC_ARM_REG_PC)
    buf = uc.reg_read(UC_ARM_REG_R1)
    data_ptr = _u32(uc, buf + 12)
    before_len = _u16(uc, buf + 16)
    data_size = _u16(uc, buf + 18)

    with _LOCK:
        if not _PENDING_EVENTS:
            preview = b""
            if data_ptr and data_size:
                n = min(before_len, data_size, 24)
                if n > 0:
                    try:
                        preview = bytes(uc.mem_read(data_ptr, n))
                    except Exception:
                        preview = b""
            _trace(
                f"RECV#{_RECV_COUNT} pc=0x{pc:08x} buf=0x{buf:08x} pending=0 pass-through len={before_len} head={preview.hex()}"
            )
            return
        event = _PENDING_EVENTS.popleft()
        pending_after = len(_PENDING_EVENTS)

    if data_size == 0:
        _trace(f"RECV#{_RECV_COUNT} pc=0x{pc:08x} buf=0x{buf:08x} data_size=0 drop_pending")
        return
    event_len = min(len(event), data_size)
    if event_len == 0:
        return
    uc.mem_write(data_ptr, event[:event_len])
    _w16(uc, buf + 16, event_len)
    _trace(
        f"RECV#{_RECV_COUNT} pc=0x{pc:08x} inject_len={event_len} pending_after={pending_after} evt_head={event[:8].hex()}"
    )

    print(
        f"[fuzzware_hooks_11] recv pc=0x{pc:08x} event={event[:12].hex()}",
        flush=False,
    )


def bt_recv_prio_bridge(uc):
    global _RECV_COUNT
    _RECV_COUNT += 1
    pc = uc.reg_read(UC_ARM_REG_PC)
    buf = uc.reg_read(UC_ARM_REG_R1)
    data_ptr = _u32(uc, buf + 12)
    before_len = _u16(uc, buf + 16)
    data_size = _u16(uc, buf + 18)

    with _LOCK:
        if not _PENDING_EVENTS:
            preview = b""
            if data_ptr and data_size:
                n = min(before_len, data_size, 24)
                if n > 0:
                    try:
                        preview = bytes(uc.mem_read(data_ptr, n))
                    except Exception:
                        preview = b""
            _trace(
                f"PRIO_RECV#{_RECV_COUNT} pc=0x{pc:08x} buf=0x{buf:08x} pending=0 pass-through len={before_len} head={preview.hex()}"
            )
            return
        event = _PENDING_EVENTS.popleft()
        pending_after = len(_PENDING_EVENTS)

    if data_size == 0:
        _trace(f"PRIO_RECV#{_RECV_COUNT} pc=0x{pc:08x} buf=0x{buf:08x} data_size=0 drop_pending")
        return
    event_len = min(len(event), data_size)
    if event_len == 0:
        return
    uc.mem_write(data_ptr, event[:event_len])
    _w16(uc, buf + 16, event_len)
    _trace(
        f"PRIO_RECV#{_RECV_COUNT} pc=0x{pc:08x} inject_len={event_len} pending_after={pending_after} evt_head={event[:8].hex()}"
    )

    print(
        f"[fuzzware_hooks_11] prio_recv pc=0x{pc:08x} event={event[:12].hex()}",
        flush=False,
    )


def _bulk_fill(uc, start, value, size):
    if size <= 0:
        return
    chunk = bytes([value & 0xFF]) * min(size, 4096)
    remain = size
    cur = start
    while remain > 0:
        n = min(remain, len(chunk))
        uc.mem_write(cur, chunk[:n])
        cur += n
        remain -= n


def _bulk_copy(uc, dst, src, size):
    if size <= 0:
        return
    chunk_size = 4096
    remain = size
    cur_dst = dst
    cur_src = src
    while remain > 0:
        n = min(remain, chunk_size)
        uc.mem_write(cur_dst, bytes(uc.mem_read(cur_src, n)))
        cur_dst += n
        cur_src += n
        remain -= n


def arch_early_memset_bridge(uc):
    pc = uc.reg_read(UC_ARM_REG_PC)
    dst = uc.reg_read(UC_ARM_REG_R0)
    value = uc.reg_read(UC_ARM_REG_R1) & 0xFF
    size = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
    max_size = int(os.getenv("VIRTBLE_FUZZWARE_EARLY_MEM_MAX", str(2 * 1024 * 1024)))
    if size > max_size:
        _trace(
            f"EARLY_MEMSET clamp pc=0x{pc:08x} dst=0x{dst:08x} size={size} -> {max_size}"
        )
        size = max_size
    _bulk_fill(uc, dst, value, size)
    _trace(f"EARLY_MEMSET pc=0x{pc:08x} dst=0x{dst:08x} val=0x{value:02x} size={size}")


def arch_early_memcpy_bridge(uc):
    pc = uc.reg_read(UC_ARM_REG_PC)
    dst = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    size = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
    max_size = int(os.getenv("VIRTBLE_FUZZWARE_EARLY_MEM_MAX", str(2 * 1024 * 1024)))
    if size > max_size:
        _trace(
            f"EARLY_MEMCPY clamp pc=0x{pc:08x} dst=0x{dst:08x} src=0x{src:08x} size={size} -> {max_size}"
        )
        size = max_size
    _bulk_copy(uc, dst, src, size)
    _trace(
        f"EARLY_MEMCPY pc=0x{pc:08x} dst=0x{dst:08x} src=0x{src:08x} size={size}"
    )


def libc_memset_bridge(uc):
    pc = uc.reg_read(UC_ARM_REG_PC)
    dst = uc.reg_read(UC_ARM_REG_R0)
    value = uc.reg_read(UC_ARM_REG_R1) & 0xFF
    size = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
    max_size = int(os.getenv("VIRTBLE_FUZZWARE_LIBC_MEM_MAX", str(1 * 1024 * 1024)))
    if size > max_size:
        _trace(
            f"LIBC_MEMSET clamp pc=0x{pc:08x} dst=0x{dst:08x} size={size} -> {max_size}"
        )
        size = max_size
    _bulk_fill(uc, dst, value, size)


def libc_memcpy_bridge(uc):
    pc = uc.reg_read(UC_ARM_REG_PC)
    dst = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    size = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
    max_size = int(os.getenv("VIRTBLE_FUZZWARE_LIBC_MEM_MAX", str(1 * 1024 * 1024)))
    if size > max_size:
        _trace(
            f"LIBC_MEMCPY clamp pc=0x{pc:08x} dst=0x{dst:08x} src=0x{src:08x} size={size} -> {max_size}"
        )
        size = max_size
    _bulk_copy(uc, dst, src, size)


def busy_wait_bridge(uc):
    pc = uc.reg_read(UC_ARM_REG_PC)
    usec = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
    _trace(f"BUSY_WAIT bypass pc=0x{pc:08x} usec={usec}")


def noop_bridge(uc):
    if os.getenv("VIRTBLE_FUZZWARE_NOOP_TRACE", "0") == "1":
        pc = uc.reg_read(UC_ARM_REG_PC)
        _trace(f"NOOP pc=0x{pc:08x}")


def ret0_bridge(uc):
    uc.reg_write(UC_ARM_REG_R0, 0)


def main_flow_probe(uc):
    if os.getenv("VIRTBLE_FUZZWARE_MAIN_FLOW_TRACE", "0") != "1":
        return
    pc = uc.reg_read(UC_ARM_REG_PC)
    r0 = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
    r1 = uc.reg_read(UC_ARM_REG_R1) & 0xFFFFFFFF
    _trace(f"MAIN_FLOW pc=0x{pc:08x} r0=0x{r0:08x} r1=0x{r1:08x}")


def func_probe(uc):
    if os.getenv("VIRTBLE_FUZZWARE_FUNC_TRACE", "0") != "1":
        return
    pc = uc.reg_read(UC_ARM_REG_PC)
    r0 = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
    r1 = uc.reg_read(UC_ARM_REG_R1) & 0xFFFFFFFF
    r2 = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
    _trace(f"FUNC pc=0x{pc:08x} r0=0x{r0:08x} r1=0x{r1:08x} r2=0x{r2:08x}")


def pc_probe(uc):
    if os.getenv("VIRTBLE_FUZZWARE_EVT_TRACE", "0") != "1":
        return
    pc = uc.reg_read(UC_ARM_REG_PC) & 0xFFFFFFFF
    r0 = uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
    r1 = uc.reg_read(UC_ARM_REG_R1) & 0xFFFFFFFF
    r2 = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
    _trace(f"PC_PROBE pc=0x{pc:08x} r0=0x{r0:08x} r1=0x{r1:08x} r2=0x{r2:08x}")


def entropy_get_bridge(uc):
    global _ENTROPY_COUNTER
    buf = uc.reg_read(UC_ARM_REG_R1) & 0xFFFFFFFF
    length = uc.reg_read(UC_ARM_REG_R2) & 0xFFFFFFFF
    if length > 0 and buf != 0:
        n = min(length, 4096)
        start = _ENTROPY_COUNTER & 0xFF
        data = bytes(((start + i) & 0xFF) for i in range(n))
        try:
            uc.mem_write(buf, data)
        except Exception:
            pass
        _ENTROPY_COUNTER = (_ENTROPY_COUNTER + n + 17) & 0xFFFFFFFF
    uc.reg_write(UC_ARM_REG_R0, 0)
    if os.getenv("VIRTBLE_FUZZWARE_FUNC_TRACE", "0") == "1":
        pc = uc.reg_read(UC_ARM_REG_PC)
        _trace(f"ENTROPY_BRIDGE pc=0x{pc:08x} buf=0x{buf:08x} len={length}")
