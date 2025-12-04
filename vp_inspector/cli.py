#!/usr/bin/env python3
"""
VirtualProtect Inspector - Command Line Interface

Provides command-line access to VirtualProtect Inspector functionality.

Author: Anubhav Gain <anubhavg@infopercept.com>
"""

import argparse
import sys
from typing import Optional

from . import __version__, __author__, __email__
from .rop_builder import ROPChainBuilder
from .gadget_finder import GadgetFinder
from .exploit_generator import ExploitGenerator
from .config import Config


def print_banner():
    """Print the tool banner."""
    banner = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██╗   ██╗██████╗     ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗ ║
║   ██║   ██║██╔══██╗    ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝ ║
║   ██║   ██║██████╔╝    ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║    ║
║   ╚██╗ ██╔╝██╔═══╝     ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║    ║
║    ╚████╔╝ ██║         ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║    ║
║     ╚═══╝  ╚═╝         ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ║
║                                                                               ║
║                    VirtualProtect DEP Bypass Toolkit                          ║
║                           Version {__version__}                                      ║
║                                                                               ║
║   Author: {__author__} <{__email__}>                               ║
║   GitHub: https://github.com/anubhavg-icpl/virtual-protect-inspector          ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def cmd_gadgets(args):
    """Generate gadget hunting guide."""
    finder = GadgetFinder(bad_chars=args.bad_chars)

    if args.modules:
        modules = args.modules.split(",")
    else:
        modules = None

    print(finder.generate_gadget_hunt_script(modules))

    if args.table:
        print(finder.print_gadget_table())


def cmd_build(args):
    """Build ROP chain from config file."""
    config = Config()

    try:
        target_config = config.import_config(args.config)
    except FileNotFoundError:
        print(f"[-] Config file not found: {args.config}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error loading config: {e}")
        sys.exit(1)

    generator = ExploitGenerator(target_config)

    if args.output:
        script = generator.export_python_exploit(
            target_ip=args.target or "192.168.0.100",
            target_port=args.port or 9999,
            output_file=args.output
        )
        print(f"[+] Exploit script written to: {args.output}")
    else:
        script = generator.export_python_exploit(
            target_ip=args.target or "192.168.0.100",
            target_port=args.port or 9999
        )
        print(script)


def cmd_preset(args):
    """List or use preset configurations."""
    config = Config()

    if args.list:
        print("\nAvailable Presets:")
        print("-" * 60)
        for name, description in config.list_presets().items():
            print(f"  {name}: {description}")
        print()
        return

    if args.name:
        try:
            target_config = config.load_preset(args.name)
            if args.export:
                config.export_config(target_config, args.export)
                print(f"[+] Configuration exported to: {args.export}")
            else:
                print(f"\nPreset: {target_config.name}")
                print(f"Description: {target_config.description}")
                print(f"Offset: {target_config.offset}")
                print(f"VirtualProtect IAT: 0x{target_config.virtualprotect_iat:08x}")
                print(f"Writable Address: 0x{target_config.writable_address:08x}")
                print(f"Protection Size: 0x{target_config.protection_size:x}")
                print(f"Protection Flag: {Config.protection_flag_name(target_config.protection_flag)}")
                print(f"\nGadgets ({len(target_config.gadgets)}):")
                for name, info in target_config.gadgets.items():
                    print(f"  {name}: 0x{info['address']:08x} ({info['module']})")
        except ValueError as e:
            print(f"[-] Error: {e}")
            sys.exit(1)


def cmd_calc(args):
    """Calculate values for ROP chain building."""
    finder = GadgetFinder()

    if args.negate:
        value = int(args.negate, 16) if args.negate.startswith("0x") else int(args.negate)
        negated = finder.get_negation_value(value)
        print(f"To get 0x{value:08x} ({value}):")
        print(f"  Load: 0x{negated:08x}")
        print(f"  Then: NEG EAX")
        print(f"  Result: 0x{value:08x}")

    if args.check_addr:
        addr = int(args.check_addr, 16) if args.check_addr.startswith("0x") else int(args.check_addr)
        bad = bytes.fromhex(args.bad_chars.replace("\\x", ""))
        is_safe = finder.check_bad_chars(addr, bad)
        print(f"Address 0x{addr:08x}: {'SAFE' if is_safe else 'CONTAINS BAD CHARS'}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="VirtualProtect Inspector - DEP Bypass ROP Chain Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s gadgets                     Generate gadget hunting guide
  %(prog)s gadgets -m essfunc,msvcrt   Search specific modules
  %(prog)s preset --list               List available presets
  %(prog)s preset vulnserver_trun      Show preset details
  %(prog)s build config.json -o exp.py Generate exploit from config
  %(prog)s calc --negate 0x40          Calculate negation value
        """
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"VirtualProtect Inspector {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Gadgets command
    gadgets_parser = subparsers.add_parser(
        "gadgets",
        help="Generate gadget hunting guide"
    )
    gadgets_parser.add_argument(
        "-m", "--modules",
        help="Comma-separated list of modules to search"
    )
    gadgets_parser.add_argument(
        "-b", "--bad-chars",
        default="\\x00",
        help="Bad characters to avoid (default: \\x00)"
    )
    gadgets_parser.add_argument(
        "-t", "--table",
        action="store_true",
        help="Include gadget purpose table"
    )
    gadgets_parser.set_defaults(func=cmd_gadgets)

    # Build command
    build_parser = subparsers.add_parser(
        "build",
        help="Build exploit from configuration"
    )
    build_parser.add_argument(
        "config",
        help="Path to configuration JSON file"
    )
    build_parser.add_argument(
        "-o", "--output",
        help="Output file for generated exploit"
    )
    build_parser.add_argument(
        "--target",
        help="Target IP address"
    )
    build_parser.add_argument(
        "--port",
        type=int,
        help="Target port"
    )
    build_parser.set_defaults(func=cmd_build)

    # Preset command
    preset_parser = subparsers.add_parser(
        "preset",
        help="Manage preset configurations"
    )
    preset_parser.add_argument(
        "name",
        nargs="?",
        help="Preset name to load"
    )
    preset_parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List available presets"
    )
    preset_parser.add_argument(
        "-e", "--export",
        help="Export preset to JSON file"
    )
    preset_parser.set_defaults(func=cmd_preset)

    # Calc command
    calc_parser = subparsers.add_parser(
        "calc",
        help="Calculate values for ROP chains"
    )
    calc_parser.add_argument(
        "-n", "--negate",
        help="Calculate negation value (e.g., 0x40)"
    )
    calc_parser.add_argument(
        "-c", "--check-addr",
        help="Check address for bad characters"
    )
    calc_parser.add_argument(
        "-b", "--bad-chars",
        default="00",
        help="Bad characters in hex (default: 00)"
    )
    calc_parser.set_defaults(func=cmd_calc)

    # Parse arguments
    args = parser.parse_args()

    # Print banner
    print_banner()

    # Execute command
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
