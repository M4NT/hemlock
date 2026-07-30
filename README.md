# Hemlock

**RAG security lab** — reproducible attack cases for retrieval-augmented generation pipelines.

Build your own RAG pipeline and break it yourself. Each attack module maps to a published paper so you understand not just *what* breaks, but *why*.

---

## Attacks implemented

| Attack | Technique | Reference |
|--------|-----------|-----------|
| `direct_injection` | Explicit instruction override via document content | Greshake et al. (2023) [arxiv:2302.12173](https://arxiv.org/abs/2302.12173) |
| `context_override` | Factual poisoning — attacker-controlled false answer via high-relevance chunk | Zou et al. (2024) [arxiv:2402.07867](https://arxiv.org/abs/2402.07867) |
| `poisoning` | Persistent backdoor — trigger-specific payload in the index | Chaudhari et al. (2024) [arxiv:2405.20485](https://arxiv.org/abs/2405.20485) |

---

## Quickstart

```bash
git clone https://github.com/M4NT/hemlock
cd hemlock
pip install -e .

cp .env.example .env
# add your ANTHROPIC_API_KEY

# run all attacks
hemlock run all

# run a specific attack
hemlock run direct_injection --model claude-haiku-4-5-20251001
hemlock run context_override --model gpt-4o-mini
hemlock run poisoning --model llama3.2  # ollama
```

---

## How it works

Each attack:

1. **Resets** the vector index
2. **Ingests** a set of legitimate documents + one or more malicious documents
3. **Queries** the pipeline with a trigger question
4. **Scores** the response — did the model follow the injected instruction?
5. **Logs** the full retrieval trace (chunks retrieved, full prompt, response)

The trace is the key output. It shows you exactly what the model received and whether the injection made it into the context.

---

## Supported LLMs

| Provider | Models | Env var |
|----------|--------|---------|
| Anthropic | `claude-*` | `ANTHROPIC_API_KEY` |
| OpenAI | `gpt-*` | `OPENAI_API_KEY` |
| Ollama | any local model | — |

---

## Project structure

```
hemlock/
├── hemlock/
│   ├── pipeline.py      # RAG pipeline with full trace logging
│   └── cli.py           # terminal interface
├── attacks/
│   ├── base.py          # Attack base class + AttackResult
│   ├── direct_injection.py
│   ├── context_override.py
│   └── poisoning.py
└── labs/                # notebooks and extended experiments
```

---

## Academic references

- Greshake et al. (2023) — *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* — [arxiv:2302.12173](https://arxiv.org/abs/2302.12173)
- Zou et al. (2024) — *PoisonedRAG: Knowledge Poisoning Attacks to Retrieval-Augmented Generation of Large Language Models* — [arxiv:2402.07867](https://arxiv.org/abs/2402.07867)
- Chaudhari et al. (2024) — *Phantom: General Trigger Attacks on Retrieval Augmented Language Generation* — [arxiv:2405.20485](https://arxiv.org/abs/2405.20485)
- OWASP LLM Top 10 — LLM01 (Prompt Injection), LLM03 (Training Data Poisoning)

---

## License

MIT
