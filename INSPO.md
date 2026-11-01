# Prior art

Found with the GitHub repository search on 2026-11-01, ordered by stars as returned. Descriptions are paraphrased from each repository's own one-line description and are what the project is known for, not a review of its code. No code was copied.

| repo | stars | known for |
|---|---|---|
| BerriAI/litellm | 62,479 | one gateway to many LLM APIs with cost tracking and guardrails |
| gitleaks/gitleaks | 30,558 | finding secrets in git history and files |
| trufflesecurity/trufflehog | 28,811 | finding, verifying and analyzing leaked credentials |
| promptfoo/promptfoo | 26,685 | testing prompts, agents and RAG; red teaming |
| Portkey-AI/gateway | 13,299 | AI gateway with a library of guardrails |
| open-policy-agent/opa | 12,421 | general-purpose policy engine |
| data-privacy-stack/presidio | 11,616 | detecting and anonymizing PII in text, images and structured data |
| NVIDIA/garak | 9,818 | LLM vulnerability scanner |
| kyverno/kyverno | 8,307 | policy as code for Kubernetes |
| guardrails-ai/guardrails | 7,576 | validators around LLM input and output |
| NVIDIA-NeMo/Guardrails | 7,404 | programmable guardrails for LLM conversations |
| Yelp/detect-secrets | 4,663 | enterprise-friendly secret detection and prevention |
| meta-llama/PurpleLlama | 4,455 | tools to assess and improve LLM security |
| protectai/llm-guard | 3,220 | security toolkit for LLM interactions (archived) |
| cedar-policy/cedar | 1,827 | authorization policy language |
| mazen160/secrets-patterns-db | 1,623 | large open database of secret-detection patterns |
| mongodb/kingfisher | 1,290 | secret detection with live validation |

## What this repository adds

- Provider-attribute policy. The decision depends on facts about the destination (trains on inputs, zero data retention, region, contract, attestation date), not only on the content. The scanners and PII tools above classify content; the gateways route; none of the descriptions above say the decision is keyed on recorded provider attributes.
- Hash-chained evidence. Every decision, including DENY, appends a record linked by sha256 to the one before it, with class counts instead of values, and a verifier refuses an edited, reordered, forged or truncated (with `--head`) log.
- Fail closed on stale attestation. A provider whose attestation is older than the policy maximum, dated in the future, incomplete, or self-contradictory is denied for all data, public included.
- Mutation-tested. 28 hand-written one-line changes to the policy and chain code must each make the suite fail.

## What it lacks compared with them

Far wider detector coverage (hundreds of secret formats, NER-based PII), live credential validation, streaming and gateway integration, and years of production use. This is a small, checkable core, not a replacement.
