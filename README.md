# Hemlock

**RAG security lab** — reproducible attack cases for retrieval-augmented generation pipelines.

Build your own RAG pipeline and break it yourself. Each attack module maps to a published paper so you understand not just *what* breaks, but *why*.

---

## Attacks implemented

| Attack | Variants | Technique | Reference |
|--------|----------|-----------|-----------|
| `direct_injection` | 3 | Explicit instruction override via document content | Greshake et al. (2023) [arxiv:2302.12173](https://arxiv.org/abs/2302.12173) |
| `context_override` | 3 | Factual poisoning — attacker-controlled false answer via high-relevance chunk | Zou et al. (2024) [arxiv:2402.07867](https://arxiv.org/abs/2402.07867) |
| `poisoning` | 3 | Persistent backdoor — trigger-specific payload in the index | Chaudhari et al. (2024) [arxiv:2405.20485](https://arxiv.org/abs/2405.20485) |
| `indirect_injection` | 3 | Payload hidden in title, footnotes, or zero-width characters | Greshake et al. (2023) + Perez & Ribeiro (2022) [arxiv:2211.09527](https://arxiv.org/abs/2211.09527) |
| `exfiltration` | 3 | Model leaks system prompt, co-retrieved chunks, or sensitive context | PLeak — Hui et al. (2024) [arxiv:2405.06823](https://arxiv.org/abs/2405.06823) |
| `jailbreak_via_context` | 3 | Safety bypass via roleplay/research/hypothetical framing in retrieved docs | Perez & Ribeiro (2022) + Wei et al. (2023) [arxiv:2307.02483](https://arxiv.org/abs/2307.02483) |
| `authority_spoofing` | 3 | Document claims to be the authoritative system config, policy, or developer override | Schulhoff et al. (2023) [arxiv:2311.16119](https://arxiv.org/abs/2311.16119) |
| `chain_of_thought_hijack` | 3 | Injected reasoning chains steer the model to attacker-controlled conclusions | BadChain — Xiang et al. (2024) [arxiv:2401.12242](https://arxiv.org/abs/2401.12242) |
| `citation_forgery` | 3 | Fake papers, standards, and official reports poison factual claims | PoisonedRAG — Zou et al. (2024) + Pan et al. (2023) [arxiv:2305.13661](https://arxiv.org/abs/2305.13661) |
| `context_flooding` | 3 | Retrieval window flooded with noise or false narrative, crowding out legit docs | Yi et al. (2023) [arxiv:2312.14197](https://arxiv.org/abs/2312.14197) |
| `invisible_markup` | 3 | Instructions hidden in HTML comments, ARIA labels, or CSS-hidden elements | Greshake et al. (2023) + Willison (2023) |
| `temporal_spoofing` | 3 | Future-dated documents override parametric knowledge; fake "recent" events | Dhingra et al. (2022) [arxiv:2108.06914](https://arxiv.org/abs/2108.06914) |
| `semantic_backdoor` | 3 | Trigger phrase activates poisoned document payload (conditional attack) | Phantom — Chaudhari et al. (2024) [arxiv:2405.20485](https://arxiv.org/abs/2405.20485) |
| `multi_hop_poisoning` | 3 | Document chains build up malicious conclusions across retrieval hops | AgentDojo — Debenedetti et al. (2024) [arxiv:2406.13352](https://arxiv.org/abs/2406.13352) |
| `cross_tenant_poisoning` | 3 | Attacker-controlled tenant docs bleed into another tenant's queries | PoisonedRAG §3.3 — Zou et al. (2024) [arxiv:2402.07867](https://arxiv.org/abs/2402.07867) |

**15 attacks × 3 variants = 45 distinct attack scenarios.**

---

## Quickstart

```bash
git clone https://github.com/M4NT/hemlock
cd hemlock
pip install -e .

cp .env.example .env
# add your ANTHROPIC_API_KEY

# run all attacks + score
hemlock score --model claude-haiku-4-5-20251001

# run a specific attack
hemlock run direct_injection --model claude-haiku-4-5-20251001
hemlock run jailbreak_via_context --model gpt-4o-mini
hemlock run temporal_spoofing --model llama3.2  # ollama

# export results
hemlock score --output markdown --out report.md
hemlock score --output json --out report.json
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

## Defenses

| Layer | Defense | What it catches |
|-------|---------|-----------------|
| Ingest | `InjectionPatternFilter` | Documents with explicit injection markers |
| Ingest | `UnicodeNormalizer` | Zero-width and invisible Unicode characters |
| Ingest | `MarkdownHeaderSanitizer` | Injection instructions in markdown headers |
| Retrieval | `InjectionChunkFilter` | Chunks with injection patterns before prompt assembly |
| Retrieval | `ProvenanceFilter` | Chunks from untrusted sources |
| Output | `ExfiltrationGuard` | Leaked credentials, secrets, or file contents |
| Output | `InjectionSuccessGuard` | Injection success markers in the response |
| Prompt | `get_prompt(level)` | Hardened system prompts (levels: baseline → l4) |

---

## Scorer

The automatic scorer cross-products all attacks × hardening levels × defense configs and produces a vulnerability matrix:

```bash
hemlock score --model claude-haiku-4-5-20251001 --output terminal
```

```
Attack                      | baseline | l1  | l2  | l3  | l4
direct_injection            | ✗ FAIL   | ✓   | ✓   | ✓   | ✓
jailbreak_via_context       | ✗ FAIL   | ✗   | ✓   | ✓   | ✓
cross_tenant_poisoning      | ✗ FAIL   | ✗   | ✗   | ✗   | ✓
...
```

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
│   ├── pipeline.py            # RAG pipeline with full trace logging
│   ├── scorer.py              # Automatic vulnerability scorer
│   └── cli.py                 # Terminal interface
├── attacks/
│   ├── base.py                # Attack ABC + AttackResult
│   ├── direct_injection.py
│   ├── context_override.py
│   ├── poisoning.py
│   ├── indirect_injection.py
│   ├── exfiltration.py
│   ├── jailbreak_via_context.py
│   ├── authority_spoofing.py
│   ├── chain_of_thought_hijack.py
│   ├── citation_forgery.py
│   ├── context_flooding.py
│   ├── invisible_markup.py
│   ├── temporal_spoofing.py
│   ├── semantic_backdoor.py
│   ├── multi_hop_poisoning.py
│   └── cross_tenant_poisoning.py
├── defenses/
│   ├── input_sanitizer.py
│   ├── chunk_filter.py
│   ├── prompt_hardening.py
│   └── output_validator.py
└── tests/
    ├── conftest.py
    ├── test_attacks.py
    ├── test_new_attacks.py
    └── test_scorer.py
```

---

## Academic references

- Greshake et al. (2023) — *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* — [arxiv:2302.12173](https://arxiv.org/abs/2302.12173)
- Zou et al. (2024) — *PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models* — [arxiv:2402.07867](https://arxiv.org/abs/2402.07867)
- Chaudhari et al. (2024) — *Phantom: General Trigger Attacks on Retrieval Augmented Language Generation* — [arxiv:2405.20485](https://arxiv.org/abs/2405.20485)
- Perez & Ribeiro (2022) — *Ignore Previous Prompt: Attack Techniques For Language Models* — [arxiv:2211.09527](https://arxiv.org/abs/2211.09527)
- Wei et al. (2023) — *Jailbroken: How Does LLM Safety Training Fail?* — [arxiv:2307.02483](https://arxiv.org/abs/2307.02483)
- Xiang et al. (2024) — *BadChain: Backdoor Chain-of-Thought Prompting for Large Language Models* — [arxiv:2401.12242](https://arxiv.org/abs/2401.12242)
- Pan et al. (2023) — *On the Risk of Misinformation Pollution with Large Language Models* — [arxiv:2305.13661](https://arxiv.org/abs/2305.13661)
- Yi et al. (2023) — *Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models* — [arxiv:2312.14197](https://arxiv.org/abs/2312.14197)
- Schulhoff et al. (2023) — *Ignore This Title and HackAPrompt* — [arxiv:2311.16119](https://arxiv.org/abs/2311.16119)
- Dhingra et al. (2022) — *Time-Sensitive Question Answering Datasets* — [arxiv:2108.06914](https://arxiv.org/abs/2108.06914)
- Debenedetti et al. (2024) — *AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents* — [arxiv:2406.13352](https://arxiv.org/abs/2406.13352)
- Hui et al. (2024) — *PLeak: Prompt Leaking Attacks against Large Language Model Applications* — [arxiv:2405.06823](https://arxiv.org/abs/2405.06823)
- OWASP LLM Top 10 — LLM01 (Prompt Injection), LLM02 (Insecure Output Handling), LLM03 (Training Data Poisoning)

---

## License

MIT
