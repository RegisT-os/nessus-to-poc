"""Adapter command-construction tests (task section 12; safe argv building).

Every command adapter must build an argument array in which the target is a
single element and no element is ever passed to a shell. These tests also pin
protocol-specific behaviour: SNI for TLS, UDP for SNMP, no community guessing.
"""

from __future__ import annotations

import pytest

from vapt_verify.adapters import all_adapters, get_adapter
from vapt_verify.adapters.base import AdapterKind, ExecutionContext


def _ctx(**kw: object) -> ExecutionContext:
    base: dict[str, object] = {
        "finding_id": "f", "asset_id": "a", "engagement_id": "e",
        "target": "192.0.2.10", "port": 443, "transport": "tcp", "params": {},
    }
    base.update(kw)
    return ExecutionContext(**base)  # type: ignore[arg-type]


def test_openssl_uses_sni_servername() -> None:
    argv = get_adapter("openssl").build_argv(_ctx(params={"vhost": "web01.example-doc.test"}))
    assert "-servername" in argv
    assert "web01.example-doc.test" in argv
    assert "192.0.2.10:443" in argv


def test_nmap_uses_udp_flag_for_udp() -> None:
    argv = get_adapter("nmap").build_argv(_ctx(port=161, transport="udp", params={}))
    assert "-sU" in argv and "-sT" not in argv


def test_nmap_uses_tcp_flag_for_tcp() -> None:
    argv = get_adapter("nmap").build_argv(_ctx(params={"scripts": ["ssl-cert"]}))
    assert "-sT" in argv
    assert argv[-1] == "192.0.2.10"


def test_sslscan_passes_sni_name() -> None:
    argv = get_adapter("sslscan").build_argv(_ctx(params={"vhost": "web01.example-doc.test"}))
    assert any(a.startswith("--sni-name=") for a in argv)


def test_testssl_connects_to_the_ip_and_only_sends_the_vhost_as_a_name() -> None:
    """A vhost is a name sent inside the connection, never the connect target.

    Handing testssl.sh the hostname alone makes it resolve that name and connect
    wherever DNS points -- which need not be the scope-approved address, nor the
    host the scanner actually saw. `--ip` pins the socket while the URI supplies
    SNI and the certificate name.
    """
    argv = get_adapter("testssl").build_argv(_ctx(params={"vhost": "web01.example-doc.test"}))
    assert "--ip" in argv
    assert argv[argv.index("--ip") + 1] == "192.0.2.10"
    assert "web01.example-doc.test:443" in argv


def test_testssl_without_a_vhost_targets_the_address_directly() -> None:
    argv = get_adapter("testssl").build_argv(_ctx())
    assert "192.0.2.10:443" in argv
    assert "--ip" not in argv


def test_ssh_audit_targets_port() -> None:
    argv = get_adapter("ssh_audit").build_argv(_ctx(port=22, transport="tcp"))
    assert argv[0] == "ssh-audit" and argv[-1] == "192.0.2.10"


def test_snmp_uses_only_given_community_no_guessing() -> None:
    argv = get_adapter("snmp").build_argv(_ctx(port=161, transport="udp",
                                               params={"community": "public"}))
    # Exactly one community value is present; nothing is iterated/guessed.
    assert argv.count("-c") == 1
    assert "public" in argv


def test_http_sets_host_header_and_url() -> None:
    argv = get_adapter("http").build_argv(_ctx(port=443, params={"vhost": "web01.example-doc.test"}))
    assert "-H" in argv
    assert any(a == "Host: web01.example-doc.test" for a in argv)
    assert any(a.startswith("https://192.0.2.10:443") for a in argv)


def test_dns_and_smb_and_ldap_build_safely() -> None:
    assert get_adapter("dns").build_argv(_ctx(port=53, transport="udp"))[0] == "dig"
    assert get_adapter("smb").build_argv(_ctx(port=445))[0] == "smbclient"
    assert get_adapter("ldap").build_argv(_ctx(port=389))[0] == "ldapsearch"


@pytest.mark.parametrize("adapter_name", ["nmap", "openssl", "http", "ssh_audit", "sslscan",
                                          "snmp", "dns", "smb", "ldap"])
def test_hostile_target_stays_single_argv_element(adapter_name: str) -> None:
    hostile = "192.0.2.10; rm -rf / #"
    argv = get_adapter(adapter_name).build_argv(_ctx(target=hostile, port=443, transport="tcp"))
    # The hostile string appears intact as its own element (never shell-split),
    # and no element is a shell operator on its own.
    joined_elements = [a for a in argv if hostile in a]
    assert joined_elements, f"{adapter_name} dropped/mangled the target"
    assert all(";" not in a or a.count(hostile) for a in argv)


def test_database_adapter_is_manual_no_execution() -> None:
    adapter = get_adapter("database")
    assert adapter.kind is AdapterKind.MANUAL
    assert "password attacks" in adapter.evidence_request(_ctx()).lower()


def test_every_registered_adapter_has_a_name_and_parse() -> None:
    for adapter in all_adapters():
        assert adapter.name
        # Command adapters must implement build_argv; manual ones must not execute.
        if adapter.kind is AdapterKind.COMMAND:
            argv = adapter.build_argv(_ctx(port=443, transport="tcp",
                                           params={"community": "public"}))
            assert isinstance(argv, list) and argv
