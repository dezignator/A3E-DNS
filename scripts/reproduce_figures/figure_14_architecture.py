#!/usr/bin/env python3
"""Figure 14 — Integrated Security Architecture of A³E-DNS (SVG).

Programmatically generates the architecture diagram as an SVG. The SVG
is deterministic given the input parameters, so the file can be
checked against ``expected_outputs/figure_14_expected.svg``.

The diagram mirrors §6.3.1 (three planes: data, control, management)
and §6.3.3 (pipeline composition Eq. 117).

Usage:
    python scripts/reproduce_figures/figure_14_architecture.py --mode toy
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src import __version__, thesis_reference  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="figure_14_architecture")
    p.add_argument("--mode", choices=("toy", "medium", "full"), default="toy")
    p.add_argument("--output", type=Path,
                   default=Path("expected_outputs/figure_14_expected.svg"))
    return p.parse_args(argv)


#: The three planes of the architecture (§6.3.1).
PLANES = {
    "Data Plane": [
        "eBPF / XDP packet capture",
        "P4 3-stage metadata extraction",
        "Adaptive Evolutionary Encryption (AEE)",
        "Quantum-Safe Homomorphic Encryption (QHE)",
    ],
    "Control Plane": [
        "Federated Learning coordinator",
        "Transformer-based anomaly detector",
        "Threat Intelligence integration (STIX/TAXII, honeypot, darknet, vendor, internal)",
        "Adaptive Multi-Protocol Sandbox (AMPS)",
    ],
    "Management Plane": [
        "Human-in-the-loop policy configuration",
        "Monitoring and visualisation (Prometheus + Grafana)",
        "Compliance and certification module",
        "Failover and recovery coordinator",
    ],
}


def _esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def _build_svg(width: int = 1400, height: int = 900) -> str:
    meta = thesis_reference()
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
    )
    # Background
    parts.append(f'<rect width="{width}" height="{height}" fill="#fafafa"/>')

    # Title
    parts.append(
        '<text x="700" y="40" text-anchor="middle" font-family="sans-serif" '
        'font-size="24" font-weight="bold" fill="#111">'
        f'{_esc("A³E-DNS — Integrated Security Architecture")}</text>'
    )
    parts.append(
        '<text x="700" y="70" text-anchor="middle" font-family="sans-serif" '
        'font-size="14" fill="#555">'
        f'{_esc(meta["chapter"])} · {_esc(meta["framework"])} · artifact v{__version__}</text>'
    )

    # Three planes
    plane_colors = {
        "Data Plane": ("#dbeafe", "#1e40af"),
        "Control Plane": ("#dcfce7", "#166534"),
        "Management Plane": ("#fef3c7", "#92400e"),
    }
    top = 110
    plane_height = 240
    plane_gap = 20
    for i, (plane, items) in enumerate(PLANES.items()):
        y = top + i * (plane_height + plane_gap)
        fill, stroke = plane_colors[plane]
        parts.append(
            f'<rect x="60" y="{y}" width="1280" height="{plane_height}" '
            f'rx="12" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        parts.append(
            f'<text x="80" y="{y + 30}" font-family="sans-serif" font-size="18" '
            f'font-weight="bold" fill="{stroke}">{_esc(plane)}</text>'
        )
        # Items in a row of cards
        n = len(items)
        card_gap = 16
        card_w = (1280 - 80 - (n - 1) * card_gap) // n
        for j, item in enumerate(items):
            cx = 80 + j * (card_w + card_gap)
            cy = y + 60
            parts.append(
                f'<rect x="{cx}" y="{cy}" width="{card_w}" height="150" rx="8" '
                f'fill="#ffffff" stroke="{stroke}" stroke-width="1"/>'
            )
            # Wrap text on 3 lines of at most ~26 chars.
            words = item.split()
            lines: list[str] = []
            cur = ""
            for w in words:
                if len(cur) + len(w) + 1 > 26 and cur:
                    lines.append(cur)
                    cur = w
                else:
                    cur = f"{cur} {w}".strip()
            if cur:
                lines.append(cur)
            for k, line in enumerate(lines[:4]):
                parts.append(
                    f'<text x="{cx + card_w // 2}" y="{cy + 40 + k * 24}" '
                    f'text-anchor="middle" font-family="sans-serif" font-size="13" '
                    f'fill="#111">{_esc(line)}</text>'
                )

    # Pipeline equation (§6.3.3, Eq. 117)
    parts.append(
        f'<rect x="60" y="880" width="1280" height="0" fill="none"/>'
    )
    parts.append(
        '<text x="700" y="872" text-anchor="middle" font-family="sans-serif" '
        'font-size="14" fill="#333">'
        'P(τ) = S_eBPF ∘ F_QHE ∘ A_FL ∘ M_sandbox   (Eq. 117)</text>'
    )
    parts.append('</svg>')
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    svg = _build_svg()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(svg, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
