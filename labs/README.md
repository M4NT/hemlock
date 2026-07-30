# Hemlock Labs

Interactive notebooks for exploring RAG security scenarios.

| Notebook | Description | Status |
|----------|-------------|--------|
| [`01_attack_walkthrough.ipynb`](01_attack_walkthrough.ipynb) | End-to-end walkthrough of a Direct Injection attack — clean vs. poisoned pipeline, retrieval trace, defense comparison, full scorer run | ✅ Available |
| [`02_defense_comparison.ipynb`](02_defense_comparison.ipynb) | Compare rule-based vs LLM-based defenses side by side — false positive rate, coverage gaps, latency tradeoff | ✅ Available |
| [`03_fuzzer_demo.ipynb`](03_fuzzer_demo.ipynb) | Adaptive fuzzer finding variants that bypass a specific defense — MockAdversary demo + LLM real (API key optional) | ✅ Available |
| [`04_scorer_analysis.ipynb`](04_scorer_analysis.ipynb) | Full scoring matrix with heatmap and bar charts by attack type and hardening level | ✅ Available |

## Running the notebooks

```bash
pip install -e ".[dev]"
pip install jupyter
jupyter lab
```

No API key required for notebook 01 — it uses `MockLLM` and in-memory ChromaDB.
