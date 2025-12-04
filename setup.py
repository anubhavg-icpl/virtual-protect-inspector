#!/usr/bin/env python3
"""
VirtualProtect Inspector - Setup Script

Author: Anubhav Gain <anubhavg@infopercept.com>
"""

from setuptools import setup, find_packages
import os

# Read README for long description
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="virtual-protect-inspector",
    version="1.0.0",
    author="Anubhav Gain",
    author_email="anubhavg@infopercept.com",
    description="A toolkit for building VirtualProtect-based DEP bypass exploits",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/anubhavg-icpl/virtual-protect-inspector",
    project_urls={
        "Bug Tracker": "https://github.com/anubhavg-icpl/virtual-protect-inspector/issues",
        "Documentation": "https://github.com/anubhavg-icpl/virtual-protect-inspector#readme",
        "Source Code": "https://github.com/anubhavg-icpl/virtual-protect-inspector",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Education",
    ],
    keywords=[
        "security",
        "exploit",
        "rop",
        "dep-bypass",
        "virtualprotect",
        "buffer-overflow",
        "penetration-testing",
        "security-research",
    ],
    python_requires=">=3.7",
    install_requires=[],  # No external dependencies
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.9",
            "mypy>=0.900",
        ],
    },
    entry_points={
        "console_scripts": [
            "vp-inspector=vp_inspector.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
