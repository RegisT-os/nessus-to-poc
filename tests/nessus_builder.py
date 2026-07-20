"""Synthetic Nessus XML builder for tests.

Everything produced here is fully synthetic and uses only RFC 5737
documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). No
real client data is ever used in fixtures (task section 3, tests 30-31).
"""

from __future__ import annotations

from xml.sax.saxutils import escape


def report_item(
    *,
    plugin_id: str,
    plugin_name: str,
    port: int = 0,
    protocol: str | None = None,
    severity: int = 0,
    family: str = "General",
    svc_name: str = "",
    cves: list[str] | None = None,
    cpes: list[str] | None = None,
    plugin_output: str | None = None,
    synopsis: str = "",
    description: str = "",
    solution: str = "",
    risk_factor: str = "",
    see_also: list[str] | None = None,
    cvss3_base_score: str = "",
    extra_elements: dict[str, str] | None = None,
    raw_port: str | None = None,
) -> str:
    """Build one ``<ReportItem>`` element as a string.

    ``raw_port`` allows injecting a deliberately malformed (non-integer) port to
    exercise the explicit parse-failure path.
    """
    port_attr = raw_port if raw_port is not None else str(port)
    proto_attr = f' protocol="{protocol}"' if protocol is not None else ""
    svc_attr = f' svc_name="{escape(svc_name)}"' if svc_name else ""
    parts = [
        f'<ReportItem port="{escape(port_attr)}"{svc_attr}{proto_attr} '
        f'severity="{severity}" pluginID="{escape(plugin_id)}" '
        f'pluginName="{escape(plugin_name)}" pluginFamily="{escape(family)}">'
    ]
    if synopsis:
        parts.append(f"<synopsis>{escape(synopsis)}</synopsis>")
    if description:
        parts.append(f"<description>{escape(description)}</description>")
    if solution:
        parts.append(f"<solution>{escape(solution)}</solution>")
    if risk_factor:
        parts.append(f"<risk_factor>{escape(risk_factor)}</risk_factor>")
    if cvss3_base_score:
        parts.append(f"<cvss3_base_score>{escape(cvss3_base_score)}</cvss3_base_score>")
    for cve in cves or []:
        parts.append(f"<cve>{escape(cve)}</cve>")
    for cpe in cpes or []:
        parts.append(f"<cpe>{escape(cpe)}</cpe>")
    for ref in see_also or []:
        parts.append(f"<see_also>{escape(ref)}</see_also>")
    if plugin_output is not None:
        parts.append(f"<plugin_output>{escape(plugin_output)}</plugin_output>")
    for tag, value in (extra_elements or {}).items():
        parts.append(f"<{tag}>{escape(value)}</{tag}>")
    parts.append("</ReportItem>")
    return "".join(parts)


def report_host(*, name: str, props: dict[str, str | list[str]], items: list[str]) -> str:
    """Build one ``<ReportHost>`` with HostProperties and report items."""
    tags: list[str] = []
    for key, value in props.items():
        values = value if isinstance(value, list) else [value]
        for v in values:
            tags.append(f'<tag name="{escape(key)}">{escape(v)}</tag>')
    return (
        f'<ReportHost name="{escape(name)}">'
        f"<HostProperties>{''.join(tags)}</HostProperties>"
        f"{''.join(items)}"
        f"</ReportHost>"
    )


def nessus_document(
    *,
    hosts: list[str],
    report_name: str = "Synthetic Test Report",
    policy_name: str = "Synthetic Example Policy",
) -> str:
    """Wrap hosts into a complete NessusClientData_v2 document."""
    return (
        '<?xml version="1.0" ?>'
        "<NessusClientData_v2>"
        f"<Policy><policyName>{escape(policy_name)}</policyName></Policy>"
        f'<Report name="{escape(report_name)}">'
        f"{''.join(hosts)}"
        "</Report>"
        "</NessusClientData_v2>"
    )


def default_host_props(ip: str, *, credentialed: bool = False, fqdn: str = "") -> dict[str, str]:
    props: dict[str, str] = {
        "host-ip": ip,
        "HOST_START": "Mon Jul 20 09:00:00 2026",
        "HOST_END": "Mon Jul 20 09:20:00 2026",
        "operating-system": "Linux Kernel 5.x",
        "Credentialed_Scan": "true" if credentialed else "false",
    }
    if fqdn:
        props["host-fqdn"] = fqdn
    return props
