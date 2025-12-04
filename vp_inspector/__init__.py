"""
VirtualProtect Inspector - DEP Bypass ROP Chain Builder

A comprehensive toolkit for building VirtualProtect-based DEP bypass exploits
for security research and educational purposes.

Author: Anubhav Gain <anubhavg@infopercept.com>
GitHub: https://github.com/anubhavg-icpl/virtual-protect-inspector
License: MIT

WARNING: This tool is for authorized security testing and educational purposes only.
"""

__version__ = "1.0.0"
__author__ = "Anubhav Gain"
__email__ = "anubhavg@infopercept.com"
__github__ = "anubhavg-icpl"

from .rop_builder import ROPChainBuilder
from .gadget_finder import GadgetFinder
from .exploit_generator import ExploitGenerator
from .config import Config

__all__ = [
    "ROPChainBuilder",
    "GadgetFinder",
    "ExploitGenerator",
    "Config",
]
