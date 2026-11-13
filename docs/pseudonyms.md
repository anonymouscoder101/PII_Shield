# Normalization and deterministic token derivation

Phase 3 task 4 adds `shield/pseudonym.py`. It derives a candidate token and a full
HMAC identity from a session key, a typed entity, and a masked source value.
`normalize_entity(EntityType, SecretStr)` returns a masked normalized value;
`derive_token(EntityType, SecretStr, SecretBytes)` returns `TokenDerivation`.
No keys or values are cached, logged, or written to disk by this module.

## Per-type normalization

| Detector type | Normalization |
| --- | --- |
| `PERSON`, `LOCATION`, `ADDRESS` | Unicode NFC, casefold, collapse Unicode whitespace to single spaces, trim surrounding whitespace, NFC again |
| `DATE_OF_BIRTH` | Same text normalization; preserve date order and separators, without guessing ambiguous numeric dates |
| `PHONE_NUMBER` | ASCII decimal digits after removing whitespace and `+()-./`; supported extension markers become `;ext=digits` |
| `CREDIT_CARD`, `US_SSN` | ASCII decimal digits after removing whitespace, hyphens and periods |
| `EMAIL_ADDRESS` | Preserve local-part case and spelling; lowercase and NFC-normalize the domain when a nonempty single-`@` value has no whitespace |
| `IP_ADDRESS` | Standard-library compressed address/interface form; preserve CIDR prefix, host bits and scope identifier spelling |
| `API_KEY`, `SECRET`, `EMPLOYEE_ID` | Exact original value, including case, Unicode form, and all whitespace |

Names/places keep punctuation and diacritics. No address-abbreviation expansion,
accent removal or NFKC compatibility folding is performed. An explicit type
controls the rule; a credential is never routed through general name casefolding.
Employee detection may match case-insensitively, but its identifier's identity
remains case-sensitive unless a later explicit policy changes that decision.

Phone normalization does not infer country codes, trunk prefixes or regions.
A national number and its international form can therefore have different
identities. Extension markers `ext`, `ext.`, `extension`, `x`, `#`, and `;ext=`
are recognized at the end; the canonical separator prevents extension digits from
aliasing a longer main number. Decimal Unicode digits are converted to their
ASCII digit values; leading zeros and order are retained. Superscripts and other
nondigit symbols are not silently folded into numbers.

For numeric, email and IP values outside the supported formatting rules, preserve
the exact original value. Resolved overlap unions can contain extra words; merely
stripping all nondigits would incorrectly merge those values with a plain number.
Fallbacks are idempotent and do not erase distinguishing content. Email domain
normalization does not perform public-suffix checks, DNS lookups or IDNA conversion.
Email local parts remain exact, including canonical Unicode differences. IP zone
identifiers remain case-sensitive, including when combined with a CIDR prefix.
No date parsing or day/month interpretation is performed for birth dates.

Empty source values are rejected. Name/place/DOB values that become empty after
whitespace normalization are rejected. Opaque secrets retain even whitespace-only
nonempty values because stripping them would change credential identity.
The implementation performs no semantic validity check such as card checksum or
phone reachability; recognizer validation happens before this layer.

## HMAC identity and display labels

A session HMAC key must contain exactly 32 bytes. Given normalized text `norm`,
the exact input is:

```text
UTF8(entity_type.value) || 0x00 || UTF8(norm)
digest = HMAC-SHA256(session_key, input)
```

Use the canonical **detector type** in the HMAC input, not the display alias.
For example, the email domain separator is `EMAIL_ADDRESS` followed by NUL.
The closed enum prevents delimiter ambiguity between types; NUL inside an opaque
value remains part of that value. Independent session keys produce independent
identities; repeated normalized inputs with the same key produce the same digest.
This implements the design document's type-separated format without hashing a
normalized value unkeyed.

| Detector type | Token label |
| --- | --- |
| `PERSON` | `PERSON` |
| `EMAIL_ADDRESS` | `EMAIL` |
| `PHONE_NUMBER` | `PHONE` |
| `CREDIT_CARD` | `CARD` |
| `US_SSN` | `SSN` |
| `LOCATION` | `LOCATION` |
| `ADDRESS` | `ADDRESS` |
| `IP_ADDRESS` | `IP` |
| `DATE_OF_BIRTH` | `DOB` |
| `API_KEY` | `APIKEY` |
| `SECRET` | `SECRET` |
| `EMPLOYEE_ID` | `EMPLOYEE` |

`TOKEN_LABELS` is immutable and labels are unique. Initial display tokens use
`[LABEL_XXXX]`, where the suffix is the first four characters of uppercase,
unpadded RFC 4648 Base32 of the digest. This is 20 display bits, not entity identity.
`TokenDerivation.entity_digest` retains all 32 bytes, excluded from representation
and model serialization. The result contains no normalized or original value.

`format_token(type, full_digest, suffix_length=...)` can extend a candidate using
only the full digest. Lengths from 4 through 32 are supported (up to 160 display
bits). The full 256-bit digest is never exported as a token, consistent with
[ADR 001](decisions/001-session-storage-and-buffered-sse.md). Reject malformed keys,
digests, lengths, types, or unencodable values with static `PseudonymError` messages
that do not include source values, normalized text or underlying exceptions.
Normalization rules, type-domain names, labels and token syntax are compatibility
decisions; changes require an explicit migration/version decision before existing
persistent sessions are reused.

## Following tasks

These are candidate derivation/formatting primitives, not a mapping allocator.
A short suffix can collide. Task 5 must compare full digests and atomically reuse
or allocate mappings, extending suffixes without overwriting another identity.
That layer also retains the first observed spelling for restoration when two
values normalize identically. No plaintext comparison or decryption is needed
for digest identity. Task 6 applies replacements to text; the gateway remains
blocked until the protected pipeline is implemented.
