# Roadmap

| Feature | Status |
|---|---|
| Interactive dashboard with NIST 800-53 score | ✅ Done |
| Findings browser with control family + DoD SRG Impact Level filters | ✅ Done |
| Demo mode (`--demo`) | ✅ Done |
| Cobra CLI with headless `report nist --format table\|json` | ✅ Done |
| Live Security Hub + Organizations integration (with single-account fallback) | ✅ Done |
| NIST → DoD SRG Impact Level crosswalk for live findings | 🔲 Planned |
| Official NIST control titles in live mode | 🔲 Planned |
| Finding detail pane (control description, RMF mapping, remediation) | 🔲 Planned |
| Report export: Markdown / HTML for ATO evidence packages | 🔲 Planned |
| Threat-modeling wizard (STRIDE, Markdown output) | 🔲 Planned |
| Scheduled execution (Lambda + EventBridge Scheduler) | 🔲 Planned |
| S3 result storage + drift detection | 🔲 Planned |
| Continuous control monitoring dashboard | 🔲 Exploring |
| Native AI workload checks (Bedrock / SageMaker: AU-12, SC-7, AC-6) mapped to NIST AI RMF and OWASP LLM Top 10 | 🔲 Planned |

The authoritative, ordered plan lives in the repository's [`CLAUDE.md`](https://github.com/willj4945/cloudcomply/blob/main/CLAUDE.md#whats-next-planned-order) and [`docs/ai-controls/plan.md`](https://github.com/willj4945/cloudcomply/blob/main/docs/ai-controls/plan.md).

Have a use case that isn't covered? [Open a feature request](https://github.com/willj4945/cloudcomply/issues/new/choose).
