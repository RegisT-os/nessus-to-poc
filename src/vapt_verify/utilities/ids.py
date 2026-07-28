"""Stable identifier and fingerprint construction.

Legacy failure mode 2.4: the old tool collapsed findings to
``name -> host -> {ports}``, losing distinct finding identities. To prevent
that, identifiers here are derived from a rich set of normalized fields so that
genuinely distinct findings receive distinct IDs, while a re-import of the same
source record is deterministic and reproducible.

Task section 9.4 requires that a finding fingerprint MUST NOT be based only on
``plugin name + IP + port``. The fingerprint below incorporates the plugin id,
host identity, port, transport, service, a digest of the plugin output and the
source provenance.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

_ID_LENGTH = 16


def stable_digest(parts: Iterable[str], length: int = _ID_LENGTH) -> str:
    """Return a stable hex digest over ``parts``, using a NUL separator.

    A NUL separator avoids ambiguity where field boundaries could otherwise be
    forged by embedding the separator character in a value.
    """
    joined = "\x00".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:length]


# Internal alias retained for readability within this module.
_digest = stable_digest


def asset_id(engagement_id: str, *, primary_key: str) -> str:
    """Stable asset id from the engagement and the asset's primary key.

    ``primary_key`` is an IP where available, otherwise a hostname/FQDN, so a
    scanner host that reports only a name still receives a stable id.
    """
    return "asset-" + _digest([engagement_id, primary_key.lower()])


def service_id(asset: str, *, port: int, transport: str, vhost: str = "") -> str:
    """Stable service-observation id.

    Virtual host / SNI is included so that different virtual hosts on one
    IP:port (legacy failure mode 2.4) are not merged.
    """
    return "svc-" + _digest([asset, str(port), transport.lower(), vhost.lower()])


def finding_fingerprint(
    *,
    plugin_id: str,
    host_key: str,
    port: int,
    transport: str,
    service: str,
    plugin_output_digest: str,
    vhost: str = "",
    cves: Iterable[str] = (),
) -> str:
    """Content fingerprint used to detect duplicate *candidates*.

    Two findings sharing a fingerprint are duplicate candidates that are
    retained separately pending review — never silently merged. The fingerprint
    deliberately spans more than ``plugin name + IP + port`` (task 9.4): it also
    reflects transport, service, virtual host, the CVE set and a digest of the
    plugin output, so that (for example) two certificates on one service or two
    distinct outputs of one plugin do not collide.
    """
    cve_part = ",".join(sorted({c.strip().upper() for c in cves if c.strip()}))
    return "fp-" + _digest(
        [
            plugin_id,
            host_key.lower(),
            str(port),
            transport.lower(),
            service.lower(),
            vhost.lower(),
            cve_part,
            plugin_output_digest,
        ],
        length=24,
    )


def finding_id(*, source_file_hash: str, host_key: str, occurrence: int, fingerprint: str) -> str:
    """Stable normalized finding id.

    Derived from the source file hash, the host and an occurrence index within
    that host, plus the content fingerprint. Including the occurrence index
    guarantees that multiple findings on one host/port (legacy failure mode 2.4)
    and repeated identical items receive distinct, reproducible ids.
    """
    return "find-" + _digest(
        [source_file_hash, host_key.lower(), str(occurrence), fingerprint],
        length=24,
    )
