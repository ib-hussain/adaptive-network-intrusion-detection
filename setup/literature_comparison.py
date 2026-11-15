"""Extract a method/settings comparison table from the papers held in researchPapers/.

The table is deliberately NOT a numeric leaderboard. Each row records what the
reference paper actually used (dataset, observation source, method family,
task) and the reason its reported score is not directly comparable with this
laboratory study. Text is read from the PDFs themselves with `pdftotext`; no
citation, number or claim is invented.
"""
from __future__ import annotations

import argparse
import csv
import re
import subprocess
import tempfile
from pathlib import Path

PAPER_DIR = Path("researchPapers/base-papers")

DATASETS = (
    "NSL-KDD", "KDD Cup 99", "UNSW-NB15", "CIC-IDS2017", "CIC-IDS2018", "CSE-CIC-IDS2018",
    "CTU-13", "CTU-Normal-7", "ToN-IoT", "Edge-IIoTset", "BoT-IoT", "CICIoT2023",
    "WUSTL-IIoT", "USTC-TFC2016", "IIoT-Dataset", "CIC-APT", "N-BASS", "IIoT23",
)

TASKS = (
    "intrusion detection", "anomaly detection", "alert prediction", "multi-stage attack detection",
    "adversarial evasion", "cross-dataset generalisation", "zero-day",
)

METHOD_FAMILIES = {
    "graph neural network": r"graph neural network|graph attention|graph convolution|graph transformer|GraphSAGE|GAT\b|graph topology",
    "recurrent / temporal": r"\bLSTM\b|\bGRU\b|temporal convolution|temporal graph",
    "transformer": r"transformer|self-attention|cross-attention",
    "ensemble tree": r"random forest|gradient boosting|XGBoost|decision tree",
    "anomaly / outlier": r"isolation forest|one-class|autoencoder|outlier",
    "adversarial training": r"adversarial training|adversarial evasion|GAN-based",
    "reinforcement learning": r"reinforcement learning|bandit|EXP3|policy gradient",
}


def _pdf_text(path: Path, pages: int = 4) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "text.txt"
        proc = subprocess.run(["pdftotext", "-f", "1", "-l", str(pages), str(path), str(out)],
                              capture_output=True, text=True, check=False)
        if proc.returncode or not out.is_file():
            return ""
        return out.read_text(encoding="utf-8", errors="ignore")


def _title(text: str, fallback: str) -> str:
    lines = [l.strip() for l in text.splitlines()[:40] if l.strip()]
    venue_re = re.compile(
        r"^(journal of|computer networks \d|international journal|cluster computing|discover computing|"
        r"scientific reports|defence technology|applied sciences|electronics|contents lists|"
        r"original research article|research article|open access|article\b|journal pre-proof|"
        r"regular contribution|www\.|https?://|open |published online|received|revised|accepted|"
        r"journal homepage|journal of network and computer|research paper|contents lists)",
        re.I)
    author_re = re.compile(r"^[A-Z][A-Za-z\-]+ et al\.")
    candidates = [l for l in lines
                  if len(l) > 20 and not venue_re.match(l) and not author_re.match(l)]
    if not candidates:
        return fallback
    title = candidates[0]
    # A title continuation line starts in lower case; an author list does not.
    idx = lines.index(title)
    for extra in lines[idx + 1:idx + 4]:
        if not extra or not extra[0].islower():
            break
        if len(title) > 160:
            break
        title += " " + extra
    return re.sub(r"\s+", " ", title).strip(" .")


def _venue(text: str) -> str:
    head = text[:1200]
    for pattern in (r"Journal of Network and Computer Applications[^\n]*",
                    r"Computer Networks \d+ \(\d{4}\)[^\n]*",
                    r"International Journal of Information Security",
                    r"Cluster Computing \(\d{4}\)[^\n]*",
                    r"Discover Computing",
                    r"Scientific Reports",
                    r"Journal of King Saud University[^\n]*",
                    r"Defence Technology[^\n]*",
                    r"Journal of Information Security and Applications[^\n]*",
                    r"Applied Sciences[^\n]*",
                    r"Electronics[^\n]*"):
        m = re.search(pattern, head)
        if m:
            return re.sub(r"\s+", " ", m.group(0)).strip()
    return "not extracted"


def _find(text: str, vocabulary) -> list[str]:
    out = []
    for term in vocabulary:
        pattern = r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])"
        if re.search(pattern, text, re.I):
            out.append(term)
    return out


def build(paper_dir: Path = PAPER_DIR):
    rows = []
    seen = set()
    for pdf in sorted(paper_dir.glob("*.pdf")):
        text = _pdf_text(pdf)
        if not text.strip():
            rows.append({"reference_file": pdf.name, "title": "text extraction failed",
                         "venue": "not extracted", "datasets_named": "", "task": "",
                         "method_family": "", "comparable_to_this_study": "no - source text could not be read"})
            continue
        title = _title(text, pdf.stem)
        if title.lower() in seen:
            continue
        seen.add(title.lower())
        datasets = _find(text, DATASETS)
        tasks = _find(text, TASKS)
        families = [name for name, pattern in METHOD_FAMILIES.items()
                    if re.search(pattern, text, re.I)]
        rows.append({
            "reference_file": pdf.name,
            "title": title,
            "venue": _venue(text),
            "datasets_named": "; ".join(datasets),
            "task": "; ".join(tasks),
            "method_family": "; ".join(families),
            "observation_source": "public benchmark dataset (offline features), not a live captured packet trace"
            if datasets else "not stated in the extracted pages",
            "comparable_to_this_study":
                "no - different dataset, different split and different label semantics; compare mechanisms only",
        })
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--paper-dir", type=Path, default=PAPER_DIR)
    args = parser.parse_args()
    rows = build(args.paper_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise FileExistsError(f"Refusing to overwrite: {args.output}")
    with args.output.open("x", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=["reference_file", "title", "venue", "datasets_named",
                                               "task", "method_family", "observation_source",
                                               "comparable_to_this_study"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {args.output} with {len(rows)} unique references")
    for row in rows:
        print(f"  - {row['title'][:90]}")


if __name__ == "__main__":
    main()
