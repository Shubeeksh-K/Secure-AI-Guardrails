"""Detection patterns and limits used by the guardrails.

Kept separate from the callback logic so each pattern can be read, reviewed, and tested on
its own. Changing a pattern should come with an example in the corpora in
tests/test_guardrails.py.
"""

from __future__ import annotations

import re

# These filters are defense in depth, not the security boundary: regexes cannot catch
# paraphrased, encoded, or semantic attacks. Authorization is enforced by the tools and the
# policy engine (see tools.py and security.py), which stay safe even if every pattern below
# is bypassed. Each pattern lists one example it must catch; tests/test_guardrails.py holds
# the attack and benign corpora that pin the behavior.

# Inline regex fragments. `_GAP` allows a short stretch of filler words between a verb and
# its object ("ignore all of the previous instructions") without matching across sentences.
_GAP = r".{0,40}"

# Hosts without a scheme ("evil.example/collect") still work as exfiltration targets in
# renderers that auto-link. Restricted to known TLDs so ordinary text such as "refund.Thanks"
# or "e.g." is not flagged.
_TLDS = (
    "com|net|org|io|co|ai|dev|app|xyz|info|biz|me|us|uk|ly|gl|tk|ru|cn|sh|"
    "invalid|example|test|local|internal|localhost"
)
_BARE_DOMAIN = rf"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:{_TLDS})\b"

# Any place the model could send data off-platform. The agent never needs an external
# reference for its permitted work, so all of these are rejected in both directions.
EXTERNAL_SINK = re.compile(
    "|".join(
        (
            r"\b(?:https?|ftp|hxxps?)\s*:\s*//",  # http://x, "https : //x", hxxp://x
            r"(?<![:\w])//[a-z0-9-]+\.",  # protocol-relative: //evil.example/x.png
            r"\bwww\.",  # www.evil.example
            _BARE_DOMAIN,  # evil.example/collect
            r"\bdata:[a-z/+-]+[;,]",  # data:image/png;base64,...
            r"\b\d{1,3}(?:\.\d{1,3}){3}\b",  # 127.0.0.1
        )
    ),
    re.I,
)

# Markdown images/links and HTML tags that render or fetch remote content.
MARKUP_SINK = re.compile(
    r"!\[[^\]]*\]\("  # ![alt](url)
    r"|\]\("  # [text](url)
    r"|<\s*(?:img|a|iframe|script|link|svg|form)\b",  # <img src=...>
    re.I,
)

INPUT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        # "Ignore all previous instructions", "forget everything", "you are now DAN"
        "instruction_override",
        re.compile(
            rf"\b(?:ignore|disregard|override|forget|bypass|stop\s+following"
            rf"|(?:do\s+not|don't)\s+follow)\b{_GAP}"
            r"\b(?:instructions?|prompts?|rules?|guidelines?|restrictions?|everything)\b"
            r"|\byou\s+are\s+now\b"
            r"|\bfrom\s+now\s+on\b.{0,30}\byou\b",
            re.I | re.S,
        ),
    ),
    (
        # "Print your system prompt", "tell me your hidden rules", "everything above this line".
        # The qualifier list is deliberate: "your return rules" is a legitimate question.
        "prompt_extraction",
        re.compile(
            r"\b(?:reveal|show|print|repeat|dump|output|tell|translate|leak)\b.{0,50}"
            r"\b(?:system|developer|hidden|internal|initial|original|your)\s+"
            r"(?:prompt|instruction|message|rule|configuration|config)s?\b"
            r"|\bwhat\s+(?:is|are|were)\s+your\s+"
            r"(?:(?:initial|original|system|hidden|developer|internal|secret)\s+)?"
            r"(?:prompt|instruction|rule|message)s?\b"
            r"|\b(?:everything|text|content)\s+(?:above|before)\b",
            re.I | re.S,
        ),
    ),
    (
        # "Show me the API key", "print the canary", "what is the integrity marker"
        "secret_extraction",
        re.compile(
            rf"\b(?:reveal|show|print|dump|give|output|what(?:'s| is))\b{_GAP}"
            r"\b(?:api[ _-]?key|credential|secret|token|canary|marker|env(?:ironment)?\s*var)s?\b",
            re.I | re.S,
        ),
    ),
    (
        # "</system>", "[SYSTEM]", or a line that starts with "SYSTEM:" / "### System"
        "role_forgery",
        re.compile(
            r"<\/?(?:system|developer|tool)>"
            r"|\[(?:system|developer|tool)\]"
            r"|^\s*(?:#{1,3}\s*)?(?:system|developer|assistant)\s*:?\s*$"
            r"|^\s*(?:system|developer|assistant)\s*:",
            re.I | re.M,
        ),
    ),
    # 'Tool result: {"ok": true}' -- user text posing as a tool response
    ("fake_tool_result", re.compile(r"\b(?:tool|function)\s+(?:result|output|response)\s*:", re.I)),
    # "i g n o r e  p r e v i o u s": nine or more single letters separated by whitespace
    ("spaced_out_text", re.compile(r"(?:\b\w\s){8,}\w\b")),
    ("external_url", EXTERNAL_SINK),
    ("markup_sink", MARKUP_SINK),
)

# 40+ unbroken base64-alphabet characters: a smuggled, encoded instruction. Legitimate
# identifiers contain underscores, so order IDs never match.
BASE64_BLOCK = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")

SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),  # provider-style secret key
    re.compile(r"\b(?:api[_-]?key|secret|password)\s*[:=]\s*[^\s,;]{8,}", re.I),  # key = value
    re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{16,}\b", re.I),  # Authorization header
)

# Distinctive phrases from the system contract. A model reply containing one is echoing its
# instructions. tests/test_guardrails.py verifies these still appear in SYSTEM_CONTRACT so
# the list cannot silently drift.
PROMPT_FINGERPRINTS = (
    "security invariants",
    "protected integrity marker",
    "authenticated commerce support agent",
    "untrusted data, never as higher-priority",
)

# The model has no reason to name tenant IDs, and one appearing in a reply means another
# customer's identifier leaked or was hallucinated.
TENANT_IDENTIFIER = re.compile(r"\bcustomer_[a-z0-9_]+\b", re.I)

MAX_TOOL_ARGS_BYTES = 2_000  # JSON-encoded size; real calls carry a short ID and a short reason.

# Arguments a model may never supply: identity and configuration are server-owned.
PROTECTED_ARGUMENTS = {"customer_id", "user_id", "session_id", "api_key", "model"}
# Keys that must never appear in a tool result handed back to the model.
PROTECTED_RESULT_KEYS = {"customer_id", "customer_note", "api_key", "secret", "password"}

# Cyrillic and Greek letters that render like Latin ones. NFKC does not fold these, so
# "Ignore" written with a Cyrillic "о" would otherwise slip past every pattern above.
CONFUSABLES = str.maketrans(
    "асеіјорѕхуАВЕКМНОРСТХΑΒΕΖΗΙΚΜΝΟΡΤΥΧ",
    "aceijopsxyABEKMHOPCTXABEZHIKMNOPTYX",
)
