"""EvalComparison — compare EvalBenchmark results across models (v3.7).

Runs (or ingests) multiple EvalReports and lines them up side by side: a
per-category score matrix, overall scores, a winner, and regression detection
against a chosen baseline model.

Usage:
    runner = EvalComparisonRunner.from_mock(["gpt-4o", "claude-3"])
    comparison = runner.run()
    print(comparison.winner())
    print(comparison.to_markdown())

Or from saved reports:
    comparison = EvalComparison.from_reports({"a": report_a, "b": report_b})
"""

from __future__ import annotations

import json
from typing import Any, Callable

from hemlock.eval_benchmark import EvalBenchmark, EvalReport


class EvalComparison:
    def __init__(self, reports: dict[str, EvalReport]) -> None:
        self.reports = reports

    @classmethod
    def from_reports(cls, reports: dict[str, EvalReport]) -> "EvalComparison":
        return cls(dict(reports))

    def _all_categories(self) -> list[str]:
        cats: set[str] = set()
        for report in self.reports.values():
            cats.update(report.category_scores())
        return sorted(cats)

    def category_matrix(self) -> dict[str, dict[str, float]]:
        matrix: dict[str, dict[str, float]] = {}
        for cat in self._all_categories():
            matrix[cat] = {
                model: report.category_scores().get(cat, 0.0)
                for model, report in self.reports.items()
            }
        return matrix

    def overall_scores(self) -> dict[str, float]:
        return {model: report.overall_score() for model, report in self.reports.items()}

    def winner(self) -> str:
        scores = self.overall_scores()
        if not scores:
            return ""
        best = max(scores.values())
        for model in scores:  # first model (insertion order) wins ties
            if scores[model] == best:
                return model
        return ""

    def regressions(self, baseline_model: str) -> dict[str, dict[str, float]]:
        """Categories where another model scores lower than the baseline.

        Returns {model: {category: delta}} with delta < 0 (model below baseline).
        """
        if baseline_model not in self.reports:
            raise KeyError(f"unknown baseline model: {baseline_model!r}")
        base_scores = self.reports[baseline_model].category_scores()
        out: dict[str, dict[str, float]] = {}
        for model, report in self.reports.items():
            if model == baseline_model:
                continue
            model_scores = report.category_scores()
            regressed: dict[str, float] = {}
            for cat, base in base_scores.items():
                cur = model_scores.get(cat, 0.0)
                if cur < base:
                    regressed[cat] = round(cur - base, 1)
            if regressed:
                out[model] = regressed
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "models": list(self.reports),
            "overall_scores": self.overall_scores(),
            "winner": self.winner(),
            "category_matrix": self.category_matrix(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        models = list(self.reports)
        overall = self.overall_scores()
        winner = self.winner()

        header = "| Category | " + " | ".join(models) + " |"
        sep = "|----------|" + "|".join(["-------"] * len(models)) + "|"
        lines = [
            "# Hemlock Eval Comparison",
            "",
            f"**Models**: {', '.join(models) or 'none'}  ",
            f"**Winner**: {winner or '—'}",
            "",
            "## Overall Scores",
            "",
            "| Model | Overall |",
            "|-------|---------|",
        ]
        for model in models:
            mark = " 🏆" if model == winner else ""
            lines.append(f"| {model}{mark} | {overall[model]} |")

        lines += ["", "## Category Matrix", "", header, sep]
        matrix = self.category_matrix()
        for cat in sorted(matrix):
            row = matrix[cat]
            lines.append(
                "| " + cat + " | " + " | ".join(str(row[m]) for m in models) + " |"
            )
        return "\n".join(lines)


class EvalComparisonRunner:
    def __init__(
        self,
        pipeline_factories: dict[str, Callable[[], Any]],
        **bench_kwargs: Any,
    ) -> None:
        self.pipeline_factories = pipeline_factories
        self.bench_kwargs = bench_kwargs

    def run(self, verbose: bool = False) -> EvalComparison:
        reports: dict[str, EvalReport] = {}
        for model_name, factory in self.pipeline_factories.items():
            pipeline = factory()
            bench = EvalBenchmark(pipeline, model_name=model_name, **self.bench_kwargs)
            reports[model_name] = bench.run(verbose=verbose)
        return EvalComparison.from_reports(reports)

    @classmethod
    def from_mock(
        cls,
        model_names: list[str],
        **bench_kwargs: Any,
    ) -> "EvalComparisonRunner":
        import tempfile

        from langchain_core.language_models.fake_chat_models import FakeListChatModel

        from hemlock.mock import MockEmbeddings
        from hemlock.pipeline import Pipeline

        def _make_factory() -> Callable[[], Any]:
            def factory() -> Any:
                tmpdir = tempfile.mkdtemp(prefix="hemlock_evalcmp_")
                llm = FakeListChatModel(responses=["This is a safe answer."] * 500)
                return Pipeline(llm=llm, persist_dir=tmpdir, embeddings=MockEmbeddings())
            return factory

        factories = {name: _make_factory() for name in model_names}
        return cls(factories, **bench_kwargs)
