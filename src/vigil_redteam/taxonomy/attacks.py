"""Operational attack taxonomy for Vigil Guard adversarial testing.

8 categories (A-H) covering the full spectrum of prompt injection
and related LLM security threats.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vigil_redteam.schema.enums import AttackCategory, DetectionLayer


@dataclass(frozen=True)
class Subcategory:
    name: str
    description: str
    expected_layers: list[DetectionLayer] = field(default_factory=list)
    severity_range: tuple[int, int] = (3, 5)


@dataclass(frozen=True)
class CategorySpec:
    category: AttackCategory
    label: str
    description: str
    subcategories: dict[str, Subcategory]


TAXONOMY: dict[AttackCategory, CategorySpec] = {
    AttackCategory.INSTRUCTION_OVERRIDE: CategorySpec(
        category=AttackCategory.INSTRUCTION_OVERRIDE,
        label="A. Instruction Override",
        description="Direct attempts to override, ignore, or supersede system instructions.",
        subcategories={
            "ignore_previous": Subcategory(
                name="Ignore Previous Instructions",
                description="Explicit demand to disregard prior instructions.",
                expected_layers=[DetectionLayer.HEURISTICS, DetectionLayer.SEMANTIC],
                severity_range=(4, 5),
            ),
            "reveal_system_prompt": Subcategory(
                name="Reveal System Prompt",
                description="Attempt to extract or display the system prompt.",
                expected_layers=[DetectionLayer.HEURISTICS, DetectionLayer.SEMANTIC],
                severity_range=(4, 5),
            ),
            "act_as_admin": Subcategory(
                name="Act as Admin / Developer",
                description="Impersonate privileged role to bypass restrictions.",
                expected_layers=[DetectionLayer.HEURISTICS, DetectionLayer.SEMANTIC],
                severity_range=(3, 5),
            ),
            "hierarchy_conflict": Subcategory(
                name="Hierarchy Conflict",
                description="Claim higher authority than the system prompt.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(3, 4),
            ),
        },
    ),
    AttackCategory.DATA_EXFILTRATION: CategorySpec(
        category=AttackCategory.DATA_EXFILTRATION,
        label="B. Data Exfiltration",
        description="Attempts to extract secrets, hidden context, or sensitive configuration.",
        subcategories={
            "reveal_secrets": Subcategory(
                name="Reveal Secrets",
                description="Direct request for API keys, passwords, tokens.",
                expected_layers=[DetectionLayer.HEURISTICS, DetectionLayer.SEMANTIC],
                severity_range=(4, 5),
            ),
            "show_hidden_context": Subcategory(
                name="Show Hidden Context",
                description="Request to display hidden or internal context.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(3, 5),
            ),
            "dump_memory": Subcategory(
                name="Dump Memory / Conversation",
                description="Attempt to extract full conversation or memory state.",
                expected_layers=[DetectionLayer.HEURISTICS, DetectionLayer.SEMANTIC],
                severity_range=(4, 5),
            ),
            "print_api_keys": Subcategory(
                name="Print API Keys / Config",
                description="Request to output configuration patterns.",
                expected_layers=[DetectionLayer.HEURISTICS],
                severity_range=(4, 5),
            ),
        },
    ),
    AttackCategory.TOOL_AGENT_ABUSE: CategorySpec(
        category=AttackCategory.TOOL_AGENT_ABUSE,
        label="C. Tool / Agent Abuse",
        description="Exploitation of tool-calling or agent capabilities.",
        subcategories={
            "call_tool_despite_policy": Subcategory(
                name="Call Tool Despite Policy",
                description="Instruct agent to use a tool that policy forbids.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(3, 5),
            ),
            "fabricate_access": Subcategory(
                name="Fabricate Tool Access",
                description="Claim existence of tools that don't exist.",
                expected_layers=[DetectionLayer.SEMANTIC],
                severity_range=(2, 4),
            ),
            "exfiltrate_via_tool": Subcategory(
                name="Exfiltrate via Tool",
                description="Use legitimate tool to leak data externally.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(4, 5),
            ),
            "command_execution": Subcategory(
                name="Command Execution Payloads",
                description="Shell commands, SQL injection, code execution attempts.",
                expected_layers=[DetectionLayer.HEURISTICS, DetectionLayer.SEMANTIC],
                severity_range=(4, 5),
            ),
        },
    ),
    AttackCategory.OBFUSCATION: CategorySpec(
        category=AttackCategory.OBFUSCATION,
        label="D. Obfuscation",
        description="Encoded, transformed, or visually disguised payloads.",
        subcategories={
            "base64": Subcategory(
                name="Base64 Encoding",
                description="Payload encoded in base64.",
                expected_layers=[DetectionLayer.LLM_GUARD],
                severity_range=(3, 5),
            ),
            "hex": Subcategory(
                name="Hex Encoding",
                description="Payload encoded in hexadecimal.",
                expected_layers=[DetectionLayer.LLM_GUARD],
                severity_range=(3, 5),
            ),
            "url_encoding": Subcategory(
                name="URL Encoding",
                description="Payload encoded with percent-encoding.",
                expected_layers=[DetectionLayer.LLM_GUARD],
                severity_range=(3, 4),
            ),
            "html_entities": Subcategory(
                name="HTML Entity Encoding",
                description="Payload using HTML character entities.",
                expected_layers=[DetectionLayer.LLM_GUARD],
                severity_range=(3, 4),
            ),
            "homoglyphs": Subcategory(
                name="Unicode Homoglyphs",
                description="Visually similar characters from different scripts.",
                expected_layers=[DetectionLayer.LLM_GUARD, DetectionLayer.SEMANTIC],
                severity_range=(3, 5),
            ),
            "mixed_language": Subcategory(
                name="Mixed Language",
                description="Payload split across PL/EN or other languages.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(3, 4),
            ),
            "code_wrapped": Subcategory(
                name="Code-Wrapped Payload",
                description="Attack hidden in code block, JSON, YAML, SQL, or markdown.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(3, 5),
            ),
        },
    ),
    AttackCategory.MULTITURN_SLOWBURN: CategorySpec(
        category=AttackCategory.MULTITURN_SLOWBURN,
        label="E. Multi-turn / Slow-burn",
        description="Attacks distributed across multiple conversation turns.",
        subcategories={
            "staged_trust": Subcategory(
                name="Staged Trust Building",
                description="Benign turns followed by escalating payload.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(3, 5),
            ),
            "payload_split": Subcategory(
                name="Payload Split Across Turns",
                description="Malicious intent split across separate messages.",
                expected_layers=[DetectionLayer.SEMANTIC],
                severity_range=(3, 5),
            ),
            "delayed_override": Subcategory(
                name="Delayed Override",
                description="Benign start, late-turn instruction override.",
                expected_layers=[DetectionLayer.HEURISTICS, DetectionLayer.SEMANTIC],
                severity_range=(3, 5),
            ),
            "context_poisoning": Subcategory(
                name="Context Poisoning",
                description="Inject malicious content into conversation context.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(4, 5),
            ),
        },
    ),
    AttackCategory.SEMANTIC_EVASION: CategorySpec(
        category=AttackCategory.SEMANTIC_EVASION,
        label="F. Semantic Evasion",
        description="Attacks using natural language to disguise malicious intent.",
        subcategories={
            "euphemistic": Subcategory(
                name="Euphemistic Attack",
                description="Malicious request phrased in innocent-sounding language.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(2, 4),
            ),
            "roleplay": Subcategory(
                name="Roleplay / Persona Hijack",
                description="Ask model to adopt persona that bypasses restrictions.",
                expected_layers=[DetectionLayer.HEURISTICS, DetectionLayer.SEMANTIC],
                severity_range=(3, 5),
            ),
            "research_pretext": Subcategory(
                name="Research / Audit Pretext",
                description="Claim payload is for research, audit, or education.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(2, 4),
            ),
            "indirect_phrasing": Subcategory(
                name="Indirect Phrasing",
                description="Malicious intent expressed indirectly or obliquely.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(2, 4),
            ),
            "quoted_payload": Subcategory(
                name="Quoted / Cited Payload",
                description="Malicious instruction presented as a quote or example.",
                expected_layers=[DetectionLayer.SEMANTIC],
                severity_range=(2, 4),
            ),
        },
    ),
    AttackCategory.CONTEXT_INCONSISTENCY: CategorySpec(
        category=AttackCategory.CONTEXT_INCONSISTENCY,
        label="G. Context Inconsistency",
        description="Legitimate-looking documents or messages with hidden payloads.",
        subcategories={
            "business_msg_hidden_override": Subcategory(
                name="Business Message + Hidden Override",
                description="Normal business email/doc with embedded injection.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(3, 5),
            ),
            "support_email_exfiltration": Subcategory(
                name="Support Email + Exfiltration",
                description="Support ticket with hidden data extraction attempt.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(4, 5),
            ),
            "document_injection": Subcategory(
                name="Document with Injected Control",
                description="Invoice, HR doc, or legal document with control sequence.",
                expected_layers=[DetectionLayer.SEMANTIC, DetectionLayer.LLM_GUARD],
                severity_range=(3, 5),
            ),
        },
    ),
    AttackCategory.SAFE_RISKY_LOOKALIKE: CategorySpec(
        category=AttackCategory.SAFE_RISKY_LOOKALIKE,
        label="H. Safe but Risky Lookalikes",
        description="Benign content that resembles attacks — critical for FP measurement.",
        subcategories={
            "benign_admin": Subcategory(
                name="Benign Admin Tasks",
                description="Legitimate admin/ops requests that look like attacks.",
                expected_layers=[],
                severity_range=(0, 0),
            ),
            "debugging_request": Subcategory(
                name="Debugging / Troubleshooting",
                description="Real debugging that mentions injection-like terms.",
                expected_layers=[],
                severity_range=(0, 0),
            ),
            "security_testing": Subcategory(
                name="Security Testing Discussion",
                description="Discussing prompt injection for education or defense.",
                expected_layers=[],
                severity_range=(0, 0),
            ),
            "code_resembling_attack": Subcategory(
                name="Code Resembling Attack",
                description="Legitimate code containing attack-like patterns.",
                expected_layers=[],
                severity_range=(0, 0),
            ),
            "redteam_discussion": Subcategory(
                name="Red Team Discussion",
                description="Discussion about red-teaming, pen testing, security audit.",
                expected_layers=[],
                severity_range=(0, 0),
            ),
        },
    ),
}


def get_all_subcategories() -> list[tuple[AttackCategory, str, Subcategory]]:
    """Return flat list of (category, subcategory_key, subcategory_spec)."""
    return [
        (spec.category, key, sub)
        for spec in TAXONOMY.values()
        for key, sub in spec.subcategories.items()
    ]


def is_benign_category(category: AttackCategory) -> bool:
    """Category H represents benign content used for FP testing."""
    return category == AttackCategory.SAFE_RISKY_LOOKALIKE
