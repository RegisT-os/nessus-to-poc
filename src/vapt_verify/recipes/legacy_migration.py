"""Legacy ``VULNERABILITIES`` migration (task section 15).

The legacy script mapped a plugin-name substring to a single Nmap script. That
map is *seed knowledge*, not complete coverage. Here each entry is converted
into a versioned recipe that:

* records the Nmap script and its role/limitations (Nmap is supporting or
  discovery-only for these, never the sole confirmation);
* names alternative tools;
* adds a manual fallback;
* NEVER uses a missing match as a reason to omit a finding.

This is used by ``vapt-verify legacy export-nmap`` to recreate (with a loud
"incomplete" warning) the old command-file experience.
"""

from __future__ import annotations

from dataclasses import dataclass

from vapt_verify.models.recipe import (
    AuthRequirement,
    NetworkPosition,
    NmapRole,
    Recipe,
    RecipeStep,
    SafetyClass,
    SelectionLayer,
    StepMode,
    VerificationFamily,
)


@dataclass(frozen=True)
class LegacyEntry:
    name: str
    scripts: list[str]
    family: VerificationFamily
    alternatives: list[str]
    role: NmapRole
    limitation: str


_TLS = VerificationFamily.TLS_CERTIFICATE
_SUP = NmapRole.SUPPORTING


def _e(
    name: str, scripts: list[str], family: VerificationFamily, alternatives: list[str],
    limitation: str,
) -> LegacyEntry:
    return LegacyEntry(name, scripts, family, alternatives, _SUP, limitation)


LEGACY_VULNERABILITIES: list[LegacyEntry] = [
    _e("SSL Certificate Cannot Be Trusted", ["ssl-cert"], _TLS, ["openssl", "testssl.sh"],
       "ssl-cert reports the presented cert but not full trust-store validation."),
    _e("SSL Self-Signed Certificate", ["ssl-cert"], _TLS, ["openssl", "testssl.sh"],
       "A load balancer/vhost may present a different certificate."),
    _e("SSL Certificate Expiry", ["ssl-cert"], _TLS, ["openssl"],
       "Clock/vhost differences can change the observed certificate."),
    _e("SSL Medium Strength Cipher Suites Supported", ["ssl-enum-ciphers"], _TLS,
       ["testssl.sh", "sslscan", "openssl"], "ssl-enum-ciphers can differ from a real handshake."),
    _e("SSL Weak Cipher Suites Supported", ["ssl-enum-ciphers"], _TLS,
       ["testssl.sh", "sslscan", "openssl"], "ssl-enum-ciphers can differ from a real handshake."),
    _e("SSL RC4 Cipher Suites Supported", ["ssl-enum-ciphers"], _TLS, ["testssl.sh", "openssl"],
       "Confirm actual RC4 negotiation with OpenSSL/testssl."),
    _e("SSL Version 2 and 3 Protocol Detection", ["ssl-enum-ciphers"], _TLS,
       ["testssl.sh", "openssl"], "Confirm SSLv2/v3 negotiation with OpenSSL/testssl."),
    _e("TLS Version 1.0 Protocol Detection", ["ssl-enum-ciphers"], _TLS, ["testssl.sh", "openssl"],
       "Confirm TLS 1.0 negotiation with OpenSSL/testssl."),
    _e("TLS Version 1.1 Protocol Detection", ["ssl-enum-ciphers"], _TLS, ["testssl.sh", "openssl"],
       "Confirm TLS 1.1 negotiation with OpenSSL/testssl."),
    _e("SSH Weak Algorithms Supported", ["ssh2-enum-algos"], VerificationFamily.SSH, ["ssh-audit"],
       "ssh2-enum-algos enumerates offers; ssh-audit is authoritative."),
    _e("SSH Weak MAC Algorithms Enabled", ["ssh2-enum-algos"], VerificationFamily.SSH,
       ["ssh-audit"], "Enumeration only; confirm negotiated MACs with ssh-audit."),
    _e("SSH Server CBC Mode Ciphers Enabled", ["ssh2-enum-algos"], VerificationFamily.SSH,
       ["ssh-audit"], "Enumeration only; confirm CBC availability with ssh-audit."),
    _e("Terminal Services Encryption Level is Medium or Low", ["rdp-enum-encryption"],
       VerificationFamily.RDP, ["administrative"],
       "Port 3389 open does not establish the RDP security posture."),
    _e("Terminal Services Doesn't Use Network Level Authentication", ["rdp-ntlm-info"],
       VerificationFamily.RDP, ["administrative"],
       "NLA posture is best confirmed via host configuration evidence."),
]

def migrated_recipes() -> list[Recipe]:
    """Return versioned recipes reconstructed from the legacy map."""
    recipes: list[Recipe] = []
    for index, entry in enumerate(LEGACY_VULNERABILITIES):
        recipe_id = f"legacy-{index:02d}-" + entry.name.lower().replace(" ", "-")[:40].strip("-")
        recipes.append(
            Recipe(
                recipe_id=recipe_id,
                version="1-legacy",
                family=entry.family,
                title=f"Legacy migration: {entry.name}",
                name_indicators=[entry.name],
                required_capabilities=[],
                optional_capabilities=["nmap", *entry.alternatives],
                auth_requirement=AuthRequirement.NONE,
                network_position=NetworkPosition.VALIDATION_SOURCE,
                safety_class=SafetyClass.ACTIVE_NONINTRUSIVE,
                nmap_role=entry.role,
                selection_layer=SelectionLayer.CATEGORY_SPECIFIC,
                assisted_steps=[
                    RecipeStep(
                        mode=StepMode.ASSISTED,
                        adapter="nmap",
                        capability="nmap",
                        description=(
                            f"Nmap {', '.join(entry.scripts)} ({entry.role.value} evidence only)."
                        ),
                        params={"scripts": entry.scripts},
                    )
                ],
                manual_steps=[
                    RecipeStep(
                        mode=StepMode.MANUAL,
                        adapter="manual",
                        description=(
                            f"Prefer {', '.join(entry.alternatives)} for authoritative evidence."
                        ),
                    )
                ],
                known_limitations=[
                    entry.limitation, "Legacy-derived recipe; coverage is not complete."
                ],
                verdict_suggestions={"positive": "likely_confirmed"},
            )
        )
    return recipes


def nmap_scripts_for_name(plugin_name: str) -> list[str] | None:
    """Return the legacy Nmap scripts for a plugin name, if any (case-insensitive)."""
    lowered = plugin_name.lower()
    for entry in LEGACY_VULNERABILITIES:
        if entry.name.lower() in lowered:
            return list(entry.scripts)
    return None
