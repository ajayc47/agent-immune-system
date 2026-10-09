"""Content normalization.

Attackers hide instructions with encodings and look-alike characters. Both the
guardrail and the stored history use the same normalized form, so a rule that
is verified against history in ClickHouse behaves identically at runtime.
"""
import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# Common Cyrillic/Greek look-alikes folded to Latin.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "В": "B",
    "М": "M", "Т": "T", "Н": "H", "К": "K",
    "α": "a", "ο": "o", "ε": "e", "ρ": "p", "ν": "v",
})

B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decode_b64_tokens(text: str) -> list[str]:
    out = []
    for tok in B64_TOKEN.findall(text):
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() for c in s) / max(len(s), 1) > 0.95:
            out.append(s)
    return out


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(ZERO_WIDTH).translate(HOMOGLYPHS)
    decoded = _decode_b64_tokens(t)
    if decoded:
        t = t + " " + " ".join(d.translate(ZERO_WIDTH).translate(HOMOGLYPHS) for d in decoded)
    t = re.sub(r"<!--|-->", " ", t)
    # Defang styles: "evil[at]mail[dot]com", "hxxps"
    t = re.sub(r"\s*\[\s*at\s*\]\s*|\s+\(at\)\s+", "@", t, flags=re.I)
    t = re.sub(r"\s*\[\s*dot\s*\]\s*|\s+\(dot\)\s+", ".", t, flags=re.I)
    t = re.sub(r"hxxp", "http", t, flags=re.I)
    t = t.lower()
    return re.sub(r"\s+", " ", t).strip()
