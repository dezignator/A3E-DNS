# ============================================================
# A3E-DNS — setup.py (legacy install, PEP 517 build)
# Thesis artifact (Chapter 6)
# ============================================================
# Maintained for `python setup.py develop` compatibility with the
# quick-start commands in README.md and Makefile. Modern installs use
# `pip install -e .` which reads pyproject.toml when present.

from __future__ import annotations

import os
import re
from pathlib import Path

from setuptools import find_packages, setup


# ---------- Metadata helpers ----------
ROOT = Path(__file__).parent.resolve()


def read_long_description() -> str:
    readme = ROOT / "README.md"
    if readme.exists():
        return readme.read_text(encoding="utf-8")
    return "A3E-DNS thesis artifact (Chapter 6)."


def read_requirements() -> list[str]:
    req = ROOT / "requirements.txt"
    if not req.exists():
        return []
    lines: list[str] = []
    for raw in req.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def read_version() -> str:
    init = ROOT / "src" / "__init__.py"
    if init.exists():
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init.read_text(encoding="utf-8"))
        if m:
            return m.group(1)
    return "1.0.0"


# ---------- Setup ----------
setup(
    name="a3e-dns",
    version=read_version(),
    description=(
        "Next-Generation Secure and Adaptive Evolutionary Encryption for "
        "DNS-over-HTTPS, DNS-over-TLS and DNS-over-QUIC — thesis artifact "
        "(Chapter 6)"
    ),
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    author="A3E-DNS Thesis Authors",
    url="https://github.com/dezignator/A3E-DNS",
    license="MIT",
    python_requires=">=3.11,<3.12",
    packages=find_packages(where="src", exclude=("tests", "tests.*")),
    package_dir={"": "src"},
    include_package_data=True,
    package_data={
        "": ["*.json", "*.yaml", "*.yml", "*.p4", "*.c"],
    },
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest==8.3.3",
            "pytest-cov==5.0.0",
            "pytest-xdist==3.6.1",
            "pytest-timeout==2.3.1",
            "hypothesis==6.112.1",
            "ruff==0.6.5",
            "mypy==1.11.2",
        ],
        "docs": [
            "sphinx",
            "sphinx-rtd-theme",
        ],
    },
    entry_points={
        "console_scripts": [
            "a3e-dns=src.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    zip_safe=False,
)
