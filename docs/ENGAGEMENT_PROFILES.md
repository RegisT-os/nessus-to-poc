# Engagement Profiles

The **core engine is generic**. It holds no permanent client-specific
assumptions. Client specifics live in **profiles**.

## Two kinds of profile

| | Location | Committed? | Contents |
|---|---|---|---|
| **Example** | `profiles/examples/<name>/` | Yes (sanitized) | Fictional data, RFC 5737 IPs only |
| **Private** | `profiles/private/<client>/` | **Never** (git-ignored) | Real client identifiers, IP ranges, hostnames, contacts, paths |

`profiles/private/` is excluded by `.gitignore` and enforced by the client-data
safety checker (see [`SECURITY.md`](SECURITY.md)). A real profile must never be
copied into fixtures.

## Sanitized example

[`profiles/examples/banking-enterprise/`](../profiles/examples/banking-enterprise/)
is a complete, fictional banking engagement using documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `.test` hostnames.
Use it as the shape for a real private profile.

## MBSB — the first operational profile (v0.5)

MBSB is the first *operational* profile and test case, **not** the architecture.
A private MBSB profile will resemble:

```
profiles/private/mbsb/
├── engagement.yaml
├── environments.yaml
├── scope.yaml
├── recipes-overrides.yaml
├── reporting.yaml
└── README.local.md
```

It may map local specifics such as Production / Disaster Recovery / Headquarters
/ UAT environments, hostname- and IP-range-based environment hints, the approved
validation source, Tenable Security Center access mode, credentialed vs.
uncredentialed scans, retest restrictions, validation windows, reporting paths
and stakeholder evidence requirements.

### Environment precedence

When assigning an environment to an asset, apply in strict order and stop at the
first match:

1. Explicit engagement configuration
2. Explicit asset mapping
3. Hostname mapping rule
4. IP-range mapping rule
5. Unknown environment

**Never** silently assign a critical environment based only on a weak hostname
guess — record low identity confidence instead (`Asset.identity_confidence_notes`).

### What a profile may and may not override

A profile **may** override: rate limits, timing templates, required evidence,
environment handling, retest wording, report-export format and internal workflow
status mappings.

A profile **must not** override the no-data-loss invariant or the reconciliation
gate.
