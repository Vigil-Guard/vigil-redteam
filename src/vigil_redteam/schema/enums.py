"""Core enumerations for the vigil-redteam framework."""

from enum import StrEnum


class AttackCategory(StrEnum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_AGENT_ABUSE = "tool_agent_abuse"
    OBFUSCATION = "obfuscation"
    MULTITURN_SLOWBURN = "multiturn_slowburn"
    SEMANTIC_EVASION = "semantic_evasion"
    CONTEXT_INCONSISTENCY = "context_inconsistency"
    SAFE_RISKY_LOOKALIKE = "safe_risky_lookalike"


class Channel(StrEnum):
    CHAT = "chat"
    EMAIL = "email"
    RAG = "rag"
    BROWSER = "browser"
    AGENT_TOOL = "agent_tool"
    DOCUMENT = "document"
    API_DIRECT = "api_direct"


class Verdict(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class Tier(StrEnum):
    GOLDEN = "golden"
    COVERAGE = "coverage"
    MUTATION = "mutation"
    LIVE_FAILURES = "live_failures"


class FailureType(StrEnum):
    FN_DIRECT = "fn_direct"
    FN_OBFUSCATED = "fn_obfuscated"
    FN_MULTITURN = "fn_multiturn"
    FN_SEMANTIC = "fn_semantic"
    FP_BUSINESS = "fp_business"
    FP_CODE = "fp_code"
    FP_SECURITY_RESEARCH = "fp_security_research"
    MIS_SEVERITY = "mis_severity"
    WRONG_LAYER = "wrong_layer"
    INCONSISTENT_REPEAT = "inconsistent_repeat"
    LATENCY_REGRESSION = "latency_regression"


class DetectionLayer(StrEnum):
    HEURISTICS = "heuristics"
    SEMANTIC = "semantic"
    LLM_GUARD = "llm_guard"
    PII = "pii"
    CONTENT_MOD = "content_mod"
    RULES = "rules"
