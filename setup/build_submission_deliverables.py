"""Assemble the submission-ready deliverables directory from stored artefacts.

Copies the canonical report and its figures, adds the claim-to-artifact table,
the reproduction guide and the final verification log, then renders an HTML
pack and — when a local renderer is available — a PDF. Nothing is rewritten:
the Markdown report is copied byte-for-byte from the report directory so the
number verifier and the submitted document cannot drift apart.

Renderers are used if present, in this order: ``google-chrome``/``chromium``
headless print-to-pdf, then LibreOffice. If none exists, the HTML pack is kept
and the missing renderer is reported; no PDF is claimed.

Usage::

    python -m setup.build_submission_deliverables --help
    python -m setup.build_submission_deliverables
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PRIMARY_RUN = "cpu_v3_main_v2_20261115T164430Z"
SEED2_RUN = "cpu_v3_main_v2_seed2_20261115T165949Z"
REPORT_REL = f"outputs/reports/{PRIMARY_RUN}"
DELIVERABLES_REL = "deliverables/phase3_submission"

SECTION_TITLES = (
    "Implementation objective and deviation log",
    "Isolated lab, safety and sensor/data provenance",
    "Scenarios, independent ground truth and the early-warning definition",
    "Dataset, preprocessing, splits and leakage controls",
    "Baselines, budgets, tuning and the CPU environment",
    "Results",
    "Ablations and error analysis",
    "Literature comparison (method-level, not numeric)",
    "Limitations and threats to validity",
    "Reproducibility appendix",
)

FIGURE_CAPTIONS = {
    "fig01_dataset_composition": "Episodes by policy, condition and profile.",
    "fig02_pr_curves": "Episode-level precision/recall curves for the three baselines.",
    "fig03_warning_coverage": "Warning coverage against false-alarm rate, with episode-bootstrap 95 % CI.",
    "fig04_policy_comparison": "Coverage-adjusted lead time, coverage, strict coverage and false-positive rate by policy.",
    "fig05_error_analysis": "Valid early warning, late alerts, misses and false alarms.",
    "fig06_lead_time": "Per-episode lead time of valid warnings.",
    "fig07_architecture": "Implementation and data-provenance diagram (describes the code, not a measurement).",
    "fig08_sensor_evidence": "The seven declared sensor checks and their outcome.",
    "fig09_seed_comparison": "Seed 1 versus seed 2 for every policy/model configuration.",
}

CSS = """
@page { size: A4; margin: 16mm 14mm; }
body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 10.2pt; line-height: 1.38; color: #111; }
h1 { font-size: 19pt; border-bottom: 2px solid #333; padding-bottom: 4px; }
h2 { font-size: 14pt; margin-top: 20px; border-bottom: 1px solid #999; padding-bottom: 2px; }
h3 { font-size: 11.5pt; margin-top: 14px; }
table { border-collapse: collapse; width: 100%; font-size: 7.4pt; margin: 8px 0; }
th, td { border: 1px solid #bbb; padding: 2.5px 3.5px; vertical-align: top; }
th { background: #efefef; }
code, pre { font-family: "DejaVu Sans Mono", monospace; font-size: 8pt; }
pre { background: #f6f6f6; border: 1px solid #ddd; padding: 6px; overflow-wrap: anywhere; white-space: pre-wrap; }
blockquote { border-left: 3px solid #999; margin-left: 0; padding-left: 10px; color: #444; }
figure { page-break-inside: avoid; margin: 12px 0; }
figure img { max-width: 100%; border: 1px solid #ddd; }
figcaption { font-size: 8.4pt; color: #333; margin-top: 4px; }
.appendix h2 { page-break-before: always; }
"""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _latest_dir(base: Path) -> Path | None:
    if not base.is_dir():
        return None
    dirs = sorted(p for p in base.iterdir() if p.is_dir())
    return dirs[-1] if dirs else None


def _figure_appendix(figures_root: Path) -> str:
    lines = ['<div class="appendix">', "<h2>Appendix A — Generated figures</h2>"]
    for sensor in ("zeek", "gateway"):
        directory = figures_root / sensor
        if not directory.is_dir():
            continue
        lines.append(f"<h3>{sensor.capitalize()} sensor</h3>")
        for png in sorted(directory.glob("fig*.png")):
            stem = png.stem
            caption = FIGURE_CAPTIONS.get(stem, stem.replace("_", " "))
            data = png.with_suffix(".data.json")
            source = (
                f' <span class="src">source data: <code>{png.relative_to(figures_root.parent).with_suffix(".data.json").as_posix()}</code></span>'
                if data.exists()
                else ""
            )
            lines.append(
                f'<figure><img src="figures/{sensor}/{png.name}" alt="{stem}">'
                f"<figcaption><strong>{stem}</strong> — {caption}{source}</figcaption></figure>"
            )
    lines.append("</div>")
    return "\n".join(lines)


def _render_html(report_md: str, figures_root: Path, title: str) -> str:
    import markdown  # imported lazily so --help works without the dependency

    body = markdown.markdown(
        report_md,
        extensions=["tables", "fenced_code", "sane_lists", "toc"],
        output_format="html5",
    )
    return f"""<!DOCTYPE html>
<html lang="en-GB"><head><meta charset="utf-8">
<title>{title}</title><style>{CSS}</style></head>
<body>{body}{_figure_appendix(figures_root)}</body></html>
"""


def _render_pdf(html: Path, pdf: Path) -> tuple[str, str]:
    for binary in ("google-chrome", "chromium", "chromium-browser"):
        executable = shutil.which(binary)
        if executable:
            cmd = [
                executable,
                "--headless=new",
                "--disable-gpu",
                "--no-pdf-header-footer",
                "--virtual-time-budget=20000",
                f"--print-to-pdf={pdf}",
                html.resolve().as_uri(),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0 and pdf.is_file() and pdf.stat().st_size > 0:
                return binary, proc.stderr.strip()[-400:]
            raise RuntimeError(
                f"{binary} failed to render a PDF (rc {proc.returncode}): {proc.stderr.strip()[-800:]}"
            )
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if soffice:
        proc = subprocess.run(
            [soffice, "--headless", "--convert-to", "pdf", "--outdir", str(pdf.parent), str(html)],
            capture_output=True,
            text=True,
        )
        produced = pdf.parent / (html.stem + ".pdf")
        if proc.returncode == 0 and produced.is_file() and produced.stat().st_size > 0:
            return "libreoffice", proc.stderr.strip()[-400:]
        raise RuntimeError(f"LibreOffice failed to render a PDF: {proc.stderr.strip()[-800:]}")
    raise FileNotFoundError(
        "no PDF renderer found (looked for google-chrome, chromium, chromium-browser, soffice)"
    )


def _validate_pdf(pdf: Path) -> dict[str, object]:
    if not shutil.which("pdftotext"):
        return {"validated": False, "reason": "pdftotext not installed"}
    proc = subprocess.run(["pdftotext", "-layout", str(pdf), "-"], capture_output=True, text=True)
    if proc.returncode != 0:
        return {"validated": False, "reason": f"pdftotext rc {proc.returncode}: {proc.stderr.strip()}"}
    text = proc.stdout
    # PDF text extraction wraps long headings across lines; compare on a
    # whitespace-normalised copy so a line break cannot masquerade as absence.
    flat = " ".join(text.split())
    headings = {title: title in flat for title in SECTION_TITLES}
    figures = [stem for stem in FIGURE_CAPTIONS if stem in text]
    return {
        "validated": True,
        "pages": text.count("\f") + 1,
        "characters": len(text),
        "title_present": "Phase 3 — Adaptive Network Intrusion Detection" in flat,
        "sections_present": headings,
        "all_sections_present": all(headings.values()),
        "figure_references": len(figures),
        "table_markers_present": ("Train policy" in flat and "Strict coverage" in flat),
    }


def main(argv: list[str] | None = None) -> int:
    repo = _repo_root()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", default=PRIMARY_RUN)
    parser.add_argument("--output", type=Path, default=repo / DELIVERABLES_REL)
    parser.add_argument("--no-pdf", action="store_true", help="build the HTML pack only")
    args = parser.parse_args(argv)

    report_dir = repo / "outputs" / "reports" / args.run
    report_md_path = report_dir / "PHASE3_REPORT.md"
    if not report_md_path.is_file():
        print(f"[deliverables] FAILED: report not found: {report_md_path}", file=sys.stderr)
        return 2

    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    stamp = _utc()
    print(f"[deliverables] {stamp} building into {out}")

    shutil.copy2(report_md_path, out / "PHASE3_REPORT.md")
    for name in (
        "claim_artifact_table.csv",
        "seed_comparison.csv",
        "gru_metrics.csv",
        "run_inventory.json",
        "report_number_verification.json",
        "literature_comparison.csv",
        "runtime_resources.csv",
    ):
        source = report_dir / name
        if source.is_file():
            shutil.copy2(source, out / name)

    figures_src = report_dir / "figures"
    figures_dst = out / "figures"
    if figures_dst.exists():
        shutil.rmtree(figures_dst)
    shutil.copytree(figures_src, figures_dst)

    report_md = report_md_path.read_text(encoding="utf-8")
    html_path = out / "PHASE3_REPORT.html"
    html_path.write_text(
        _render_html(report_md, figures_dst, "Phase 3 — Adaptive Network Intrusion Detection"), encoding="utf-8"
    )
    print(f"[deliverables] wrote {html_path}")

    (out / "REPRODUCE.md").write_text(
        f"""# Reproduction guide (submission pack)

Canonical source: `{REPORT_REL}/PHASE3_REPORT.md` in the repository.
This directory is a copy; the repository copy is authoritative.

* `PHASE3_REPORT.md` / `.html` — the final report (10 sections).
* `figures/` — PNG figures and their `.data.json` source data.
* `claim_artifact_table.csv` — every reported value mapped to its artefact.
* `seed_comparison.csv` — seed 1 versus seed 2.
* `report_number_verification.json` — machine check of the report's numbers.
* `final_verification/` — the verification run (compileall, shell syntax, tests).
* `literature_comparison.csv`, `runtime_resources.csv`, `run_inventory.json`.

To re-verify the numbers against the stored artefacts:

```bash
python -m setup.verify_report_numbers \\
  --zeek-study outputs/studies/{PRIMARY_RUN}_zeek_20261115T165446Z \\
  --gateway-study outputs/studies/{PRIMARY_RUN}_gateway_20261115T165446Z \\
  --gru-csv outputs/reports/{PRIMARY_RUN}/gru_metrics.csv \\
  --audit outputs/audits/{PRIMARY_RUN}/sensor_audit.json \\
  --inventory outputs/reports/{PRIMARY_RUN}/run_inventory.json \\
  --seed2-study outputs/studies/{SEED2_RUN}_zeek_20261115T170436Z \\
  --seed2-gru-csv outputs/reports/{SEED2_RUN}/gru_metrics.csv
```

Raw PCAPs and run directories are Git-ignored by design and travel in the
submission evidence bundle built by `setup/package_phase3_submission.py`.
""",
        encoding="utf-8",
    )

    verification = _latest_dir(repo / "outputs" / "logs" / "final_verification")
    if verification is not None:
        dst = out / "final_verification"
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(verification, dst)
        print(f"[deliverables] copied verification log {verification.name}")

    status = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "run": args.run,
        "report_sha256": _sha256(out / "PHASE3_REPORT.md"),
        "html": str(html_path),
        "pdf": None,
        "renderer": None,
        "pdf_validation": None,
    }

    if not args.no_pdf:
        pdf_path = out / "PHASE3_REPORT.pdf"
        try:
            renderer, note = _render_pdf(html_path, pdf_path)
        except FileNotFoundError as exc:
            print(f"[deliverables] NO PDF: {exc}", file=sys.stderr)
            status["pdf_error"] = str(exc)
        except RuntimeError as exc:
            print(f"[deliverables] NO PDF: {exc}", file=sys.stderr)
            status["pdf_error"] = str(exc)
        else:
            status["pdf"] = str(pdf_path)
            status["renderer"] = renderer
            status["pdf_validation"] = _validate_pdf(pdf_path)
            print(f"[deliverables] wrote {pdf_path} via {renderer}")
            print(f"[deliverables] pdf validation: {json.dumps(status['pdf_validation'])}")

    (out / "deliverables_status.json").write_text(
        json.dumps(status, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(status, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
