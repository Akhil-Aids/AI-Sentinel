# AI Sentinel — IEEE Base Paper

## Files

| File | Purpose |
|------|---------|
| `AI_Sentinel_IEEE_Paper.tex` | The paper (IEEEtran conference format, single file, self-contained bibliography) |

## Compile

Any TeX distribution (TeX Live, MiKTeX, MacTeX) ships `IEEEtran.cls`.

```bash
cd docs/paper
pdflatex AI_Sentinel_IEEE_Paper.tex   # pass 1
pdflatex AI_Sentinel_IEEE_Paper.tex   # pass 2 (resolves \ref)
```

Output: `AI_Sentinel_IEEE_Paper.pdf`. No external `.bib`, image, or
`.sty` files are required — the bibliography is a manual `thebibliography`
environment and the architecture diagram is drawn in LaTeX (Fig. 1), so the
document compiles standalone.

**Overleaf:** upload the `.tex`, set compiler to **pdfLaTeX**.

## Target length

The source is a **base / full draft**. A typical IEEE conference target is
8 pages (2-column, 10pt) or 12 pages for a journal-style submission. This
draft runs approximately 10–11 pages as-is.

To fit a strict 8-page conference limit, cut in this order:

1. §V (Defects) → compress to a single paragraph inside §VII. *(Biggest
   gain; the material also works as a separate short paper.)*
2. §II (Related Work) → 2 paragraphs instead of 5 subsections.
3. §IV-D Supporting Assurance Controls → single bullet list.
4. Fig. 1 → reduce to 5 boxes (merge ingestion into the queue box).
5. §VIII Threats to Validity → 1 paragraph; fold content into §VII.

Keep §III, §IV-A/B/C, §VII, and §IX — they carry the contributions.

## Data provenance

Every number in §VII was measured from the live deployment, not a synthetic
harness, using the lifecycle timestamps described in Table I. To regenerate:

```powershell
cd backend
..\venv\Scripts\python.exe -m pytest -q          # 170 tests
```

The latency tables were computed by reading the persisted lifecycle columns
(`ingested_at`, `processed_at`, `detected_at`, `alert_created_at`,
`incident_created_at`, `dashboard_delivered_at`) from `data/sentinel.db`.

### Evaluation-induced defects (reported in §V)

Two silent defects were found while collecting these measurements. Both are
fixed and committed (`18b2e80`):

- **H1** `correlate.py:140` — `NameError` in the cross-family correlation
  branch; silently dropped the malware/suspicious-executable detection class
  (2,206 `pipeline.process_error` rows).
- **H2** `db.update_incident` — column allow-list omitted `timeline`,
  `mitre`, `risk_score`, `category`, `event_ids`; incident evidence never
  accumulated after creation.

§V argues that §IV-D (data quality center) is what surfaced H1, which is the
paper's central thesis. **If you shorten the paper, do not cut §V without
also weakening the abstract's claim** — the defects are the evidence, not an
anecdote.

## Honesty constraints on edits

If you revise the paper, keep these constraints. They are what distinguish it
from a typical fabricated-results SOC paper:

- Do **not** report MTTA or MTTR values. They have zero samples (no analyst
  acknowledged/resolved an incident during evaluation). Reporting a number
  here would invalidate the paper's own thesis.
- Do **not** report detection accuracy, precision, or recall. There is no
  labeled corpus. §VIII states this; §I and §VII-A must not contradict it.
- Do **not** convert the `n=11` end-to-end latency sample into a latency
  *guarantee*. It supports the architectural claim only.
- The **101.7** alert-compression ratio is campaign-dependent and is flagged
  as such in §VII-C. Do not generalize it.
- The **anomaly rate 0.05** mirrors the configured contamination parameter;
  it is not a validated operating characteristic. §VIII says so explicitly.
