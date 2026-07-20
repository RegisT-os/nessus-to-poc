"""Safe verification adapters and their registry."""

from __future__ import annotations

from vapt_verify.adapters.base import (
    Adapter,
    AdapterKind,
    Connector,
    ExecutionContext,
    ParsedResult,
    RawResult,
    RealCommandRunner,
    RealConnector,
)
from vapt_verify.adapters.dns import DnsAdapter
from vapt_verify.adapters.evidence_request import (
    AdministrativeAdapter,
    CredentialedAdapter,
    ManualAdapter,
)
from vapt_verify.adapters.http import HttpAdapter
from vapt_verify.adapters.ldap import LdapAdapter
from vapt_verify.adapters.nmap import NmapAdapter
from vapt_verify.adapters.openssl import OpensslAdapter
from vapt_verify.adapters.smb import SmbAdapter
from vapt_verify.adapters.snmp import SnmpAdapter
from vapt_verify.adapters.ssh_audit import SshAuditAdapter
from vapt_verify.adapters.sslscan import SslscanAdapter
from vapt_verify.adapters.tcp import TcpConnectAdapter
from vapt_verify.adapters.testssl import TestsslAdapter

_ADAPTERS: dict[str, Adapter] = {
    a.name: a
    for a in [
        TcpConnectAdapter(),
        NmapAdapter(),
        OpensslAdapter(),
        HttpAdapter(),
        TestsslAdapter(),
        SslscanAdapter(),
        SshAuditAdapter(),
        DnsAdapter(),
        SnmpAdapter(),
        SmbAdapter(),
        LdapAdapter(),
        ManualAdapter(),
        AdministrativeAdapter(),
        CredentialedAdapter(),
    ]
}


def get_adapter(name: str) -> Adapter | None:
    return _ADAPTERS.get(name)


def all_adapters() -> list[Adapter]:
    return list(_ADAPTERS.values())


__all__ = [
    "Adapter",
    "AdapterKind",
    "Connector",
    "ExecutionContext",
    "ParsedResult",
    "RawResult",
    "RealCommandRunner",
    "RealConnector",
    "all_adapters",
    "get_adapter",
]
