"""Shared detection patterns.

Single source of truth for regexes used by security detectors AND by log
redaction, so the two can never drift apart. All patterns are tuned to reduce
false positives on legitimate security documentation (see data/security_tests).
"""
from __future__ import annotations

import re

# --- Secrets -----------------------------------------------------------------
# AWS access key id (AKIA/ASIA + 16 uppercase alphanumerics)
AWS_ACCESS_KEY_PATTERN = re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b")
AWS_SECRET_KEY_PATTERN = re.compile(
    r"\b(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])\b"
)
# JWT: three base64url segments
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b"
)
BEARER_TOKEN_PATTERN = re.compile(
    r"\b[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*\b", re.MULTILINE
)
# GitHub personal access token (classic + fine-grained)
GITHUB_TOKEN_PATTERN = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b")
SLACK_TOKEN_PATTERN = re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
)
DATABASE_URL_PATTERN = re.compile(
    r"\b\w+(?:\+\w+)?://[^\s:@$]+:[^\s:@$]+@[^\s/$.?#].[^\s]*\b"
)
GOOGLE_API_KEY_PATTERN = re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")
STRIPE_KEY_PATTERN = re.compile(r"\b((?:sk|pk)_(?:test|live)_[A-Za-z0-9]{10,})\b")

# password/secret assignment in text: password=..., "password": ..., "password is ..."
# NOTE: the keyword list uses non-capturing groups; the secret value is the
# named group 'value' (a capture group in the keyword list once caused the
# detector to redact the literal word "or" everywhere).
SECRET_KEYWORD_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key|"
    r"client[_-]?secret|auth[_-]?token|passw(?:or)?d|passwd|pwd)\b\s*"
    r"(?:[:=]|\bis)\s*['\"]?(?P<value>[^\s'\"]{6,})"
)

# --- PII ----------------------------------------------------------------------
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
# Phone: requires separators or a leading + so bare digit runs (order numbers,
# ids) are not flagged. Matches +1 555 123 4567, (030) 1234567, 555-123-4567.
PHONE_PATTERN_INTERNATIONAL = re.compile(
    r"(?:\+\d{1,3}[-. ])?(?:\(\d{1,4}\)[-. ])?\d{2,4}[-. ]\d{3,4}[-. ]\d{3,4}\b"
)
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:\d[ -]?){13,16}\b"
)
IP_ADDRESS_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")

# --- Prompt injection -----------------------------------------------------------
# Directive verbs commonly used in instruction-override attacks. Kept as fragments
# so they can be combined with sentence structure checks in the detector.
INJECTION_DIRECTIVES = (
    "ignore previous", "ignore all previous", "ignore above", "ignore prior",
    "disregard previous", "disregard all previous", "disregard the above",
    "forget previous", "forget all previous", "forget your instructions",
    "override your instructions", "override the system", "new instructions",
    "updated instructions", "system prompt:", "you are now", "from now on you are",
    "act as if you have no restrictions", "you must obey", "obey my commands",
)

EXTRACTION_PHRASES = (
    "reveal your system prompt", "reveal your instructions",
    "show your system prompt", "print your system prompt", "what is your system prompt",
    "what are your instructions", "repeat your system prompt", "repeat the text above",
    "output your initial instructions", "print your initial prompt",
    "developer message", "system message:", "<|im_start|>", "<|system|>",
    "[INST]", "<<SYS>>", "###System:", "### System:",
)

# --- Jailbreak ------------------------------------------------------------------
JAILBREAK_PHRASES = (
    "do anything now", "DAN mode", "developer mode", "jailbreak",
    "no restrictions", "without restrictions", "no limits", "no rules apply",
    "bypass the filter", "bypass safety", "bypass your guidelines",
    "ignore safety guidelines", "ignore your content policy",
    "you can do anything", "you have no filters", "ethical constraints removed",
    "amoral ai", "unfiltered ai", "uncensored mode",
    "simulate a persona without", "roleplay as an ai without",
)

# --- RAG poisoning (documents embedding instructions to the LLM) -----------------
POISONING_PHRASES = (
    "ignore the user's question", "ignore the user question",
    "instead of answering", "respond with the following",
    "reply with the following", "output the following text",
    "instruct the assistant", "instruct the model", "tell the assistant to",
    "tell the model to", "the assistant must now", "the ai must now",
    "when asked about", "always respond with", "always answer with",
    "secretly", "covertly include", "do not mention this instruction",
    "do not reveal this instruction", "hide this from the user",
    "append your system prompt", "include your system prompt in the answer",
    "reveal api keys", "reveal credentials", "exfiltrate", "send data to",
    "forward all conversations to", "disable your safety",
)

# Document text that legitimately contains policy language but should NOT be
# treated as poisoning by itself (used to suppress naive keyword false positives).
LEGITIMATE_POLICY_MARKERS = (
    "this document", "the following policy", "company policy", "our policy",
    "employees must", "users must", "administrators must", "it is required that",
    "in accordance with", "shall be", "must comply", "for internal use",
)

# --- Unsafe URLs ---------------------------------------------------------------
UNSAFE_URL_PATTERN = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|\[::1\])",
    re.IGNORECASE,
)


def phrase_matcher(phrases: tuple[str, ...], flags: int = re.IGNORECASE) -> re.Pattern[str]:
    """Compile a tuple of literal phrases into one alternation pattern."""
    escaped = sorted((re.escape(p) for p in phrases), key=len, reverse=True)
    return re.compile("|".join(escaped), flags)
