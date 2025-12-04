"""
ROP Gadget Finder Utilities

Provides helper functions and mona.py command generators
for finding ROP gadgets in Windows binaries.

Author: Anubhav Gain <anubhavg@infopercept.com>
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class GadgetPattern:
    """Represents a gadget pattern to search for."""
    name: str
    pattern: str
    description: str
    alternatives: List[str] = None

    def __post_init__(self):
        if self.alternatives is None:
            self.alternatives = []


class GadgetFinder:
    """
    Generates mona.py commands and provides guidance for finding ROP gadgets.

    This class helps users find the necessary gadgets for building
    VirtualProtect DEP bypass ROP chains.
    """

    # Standard gadget patterns needed for VirtualProtect bypass
    REQUIRED_GADGETS = {
        "pop_ebp": GadgetPattern(
            name="pop_ebp",
            pattern="pop ebp # ret",
            description="Stack alignment gadget",
            alternatives=["pop ebp # pop xxx # ret"]
        ),
        "pop_eax": GadgetPattern(
            name="pop_eax",
            pattern="pop eax # ret",
            description="Load value into EAX",
            alternatives=["pop eax # pop xxx # ret"]
        ),
        "neg_eax": GadgetPattern(
            name="neg_eax",
            pattern="neg eax # ret",
            description="Negate EAX (for avoiding null bytes)",
            alternatives=["not eax # inc eax # ret"]
        ),
        "xchg_eax_ebx": GadgetPattern(
            name="xchg_eax_ebx",
            pattern="xchg eax, ebx # ret",
            description="Move EAX to EBX (dwSize parameter)",
            alternatives=["mov ebx, eax # ret", "push eax # pop ebx # ret"]
        ),
        "xchg_eax_edx": GadgetPattern(
            name="xchg_eax_edx",
            pattern="xchg eax, edx # ret",
            description="Move EAX to EDX (flNewProtect parameter)",
            alternatives=["mov edx, eax # ret", "push eax # pop edx # ret"]
        ),
        "pop_ecx": GadgetPattern(
            name="pop_ecx",
            pattern="pop ecx # ret",
            description="Load writable address for lpflOldProtect",
            alternatives=["pop ecx # pop xxx # ret"]
        ),
        "pop_edi": GadgetPattern(
            name="pop_edi",
            pattern="pop edi # ret",
            description="Load ROP NOP address",
            alternatives=["pop edi # pop xxx # ret"]
        ),
        "pop_esi": GadgetPattern(
            name="pop_esi",
            pattern="pop esi # ret",
            description="Load JMP [EAX] gadget address",
            alternatives=["pop esi # pop xxx # ret"]
        ),
        "jmp_eax": GadgetPattern(
            name="jmp_eax",
            pattern="jmp dword ptr [eax]",
            description="Jump to address pointed by EAX",
            alternatives=["call dword ptr [eax]"]
        ),
        "pushad": GadgetPattern(
            name="pushad",
            pattern="pushad # ret",
            description="Push all registers to stack",
            alternatives=[]
        ),
        "jmp_esp": GadgetPattern(
            name="jmp_esp",
            pattern="jmp esp",
            description="Jump to shellcode on stack",
            alternatives=["call esp", "push esp # ret"]
        ),
        "rop_nop": GadgetPattern(
            name="rop_nop",
            pattern="ret",
            description="Simple RET instruction (ROP NOP)",
            alternatives=["retn", "ret 0"]
        ),
    }

    def __init__(self, bad_chars: str = "\\x00"):
        """
        Initialize the GadgetFinder.

        Args:
            bad_chars: Bad characters to avoid (mona.py format)
        """
        self.bad_chars = bad_chars
        self.found_gadgets: Dict[str, int] = {}

    def get_mona_command(self, gadget_name: str, modules: str = "") -> str:
        """
        Generate a mona.py command to find a specific gadget.

        Args:
            gadget_name: Name of the gadget to find
            modules: Comma-separated list of modules to search

        Returns:
            mona.py command string
        """
        if gadget_name not in self.REQUIRED_GADGETS:
            raise ValueError(f"Unknown gadget: {gadget_name}")

        pattern = self.REQUIRED_GADGETS[gadget_name]
        module_arg = f' -m "{modules}"' if modules else ""

        return f'!py mona find -type instr -s "{pattern.pattern}"{module_arg} -cpb "{self.bad_chars}"'

    def get_all_mona_commands(self, modules: Dict[str, str] = None) -> List[str]:
        """
        Generate all mona.py commands needed to find gadgets.

        Args:
            modules: Dict mapping gadget names to preferred modules
                     e.g., {"pushad": "msvcrt", "neg_eax": "kernel32"}

        Returns:
            List of mona.py commands
        """
        if modules is None:
            modules = {}

        commands = []
        for gadget_name in self.REQUIRED_GADGETS:
            module = modules.get(gadget_name, "")
            cmd = self.get_mona_command(gadget_name, module)
            commands.append(f"# {self.REQUIRED_GADGETS[gadget_name].description}")
            commands.append(cmd)
            commands.append("")

        return commands

    def generate_gadget_hunt_script(self, target_modules: List[str] = None) -> str:
        """
        Generate a complete gadget hunting guide with mona.py commands.

        Args:
            target_modules: List of modules to search (e.g., ["essfunc.dll", "msvcrt.dll"])

        Returns:
            Formatted guide string
        """
        if target_modules is None:
            target_modules = ["essfunc", "msvcrt", "kernel32", "kernelbase", "ntdll", "ws2_32"]

        module_str = ",".join(target_modules)

        guide = f"""
================================================================================
VirtualProtect DEP Bypass - ROP Gadget Hunting Guide
================================================================================
Author: Anubhav Gain <anubhavg@infopercept.com>
Target Modules: {module_str}
Bad Characters: {self.bad_chars}
================================================================================

STEP 1: Find Non-ASLR Modules
-----------------------------
Run this command to identify modules without ASLR:

    !py mona modules

Look for modules with 'False' in the ASLR column.


STEP 2: Find VirtualProtect in IAT
----------------------------------
Examine the target module's IAT to find VirtualProtect:

    !dh essfunc -f
    dps essfunc+0x6000 L100

Look for 'VirtualProtect' or 'VirtualProtectStub' in the output.


STEP 3: Find Writable Memory
----------------------------
Find a writable memory region for lpflOldProtect:

    !dh kernel32
    !vprot <address>

Look for regions with PAGE_READWRITE permission.


STEP 4: Find Required Gadgets
-----------------------------
"""

        # Add gadget search commands
        for name, pattern in self.REQUIRED_GADGETS.items():
            guide += f"""
{name.upper()} - {pattern.description}
{'-' * (len(name) + len(pattern.description) + 3)}
Primary pattern: {pattern.pattern}
"""
            if pattern.alternatives:
                guide += f"Alternatives: {', '.join(pattern.alternatives)}\n"

            guide += f"""
Command:
    !py mona find -type instr -s "{pattern.pattern}" -m "{module_str}" -cpb "{self.bad_chars}"

"""

        guide += """
================================================================================
STEP 5: Verify Gadgets
================================================================================
For each gadget found, verify it in the debugger:

    u <address>

Ensure the gadget does exactly what you expect and doesn't have side effects.


================================================================================
STEP 6: Build the ROP Chain
================================================================================
Once you have all gadgets, use the ROPChainBuilder class:

    from vp_inspector import ROPChainBuilder

    builder = ROPChainBuilder()
    builder.set_virtualprotect_iat(0x6250609c)
    builder.set_writable_address(0x7653a3c1)
    builder.add_gadget("pop_ebp", 0x775d8836, "POP EBP; RET", "msvcrt.dll")
    # ... add all other gadgets
    rop_chain = builder.build()

================================================================================
"""
        return guide

    def print_gadget_table(self) -> str:
        """Print a table of all required gadgets and their purposes."""
        table = """
+------------------+--------------------------------+------------------------------+
| Register/Gadget  | Purpose in VirtualProtect      | After PUSHAD Stack Position  |
+------------------+--------------------------------+------------------------------+
| EAX              | Ptr to VirtualProtect IAT      | [ESP+28]                     |
| ECX              | lpflOldProtect (writable addr) | [ESP+24]                     |
| EDX              | flNewProtect (0x40)            | [ESP+20]                     |
| EBX              | dwSize (size of region)        | [ESP+16]                     |
| ESP              | lpAddress (auto-set)           | [ESP+12]                     |
| EBP              | Placeholder/alignment          | [ESP+8]                      |
| ESI              | JMP [EAX] gadget address       | [ESP+4]  <- Return address   |
| EDI              | ROP NOP (ret instruction)      | [ESP+0]                      |
+------------------+--------------------------------+------------------------------+

VirtualProtect Parameters After PUSHAD:
  - lpAddress:      ESP value (points to shellcode)
  - dwSize:         EBX value (e.g., 0x201)
  - flNewProtect:   EDX value (0x40 = PAGE_EXECUTE_READWRITE)
  - lpflOldProtect: ECX value (writable memory address)
"""
        return table

    def get_negation_value(self, target: int) -> int:
        """
        Calculate the value to negate to get the target value.
        Useful for avoiding null bytes.

        Args:
            target: The target value (e.g., 0x40 for PAGE_EXECUTE_READWRITE)

        Returns:
            The value that when negated gives the target
        """
        return (0xFFFFFFFF - target + 1) & 0xFFFFFFFF

    def check_bad_chars(self, address: int, bad_chars: bytes = b"\x00") -> bool:
        """
        Check if an address contains bad characters.

        Args:
            address: The address to check
            bad_chars: Bytes of bad characters to check for

        Returns:
            True if the address is safe (no bad chars), False otherwise
        """
        addr_bytes = address.to_bytes(4, "little")
        return not any(b in addr_bytes for b in bad_chars)

    def suggest_alternatives(self, gadget_name: str) -> List[str]:
        """Get alternative patterns for a gadget."""
        if gadget_name in self.REQUIRED_GADGETS:
            return self.REQUIRED_GADGETS[gadget_name].alternatives
        return []
