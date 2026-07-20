# Example profile: banking-enterprise (sanitized)

This directory is a **sanitized, fictional** engagement profile. It exists so
that documentation, demos and tests have something realistic to reference
without exposing any real client.

- All addresses use RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- All hostnames use the reserved `.test` TLD.
- No credentials are stored — only opaque `credential_references`.

To run a real engagement, copy this shape into `profiles/private/<client>/`
(which is git-ignored) and fill in the real values. See
[`docs/ENGAGEMENT_PROFILES.md`](../../../docs/ENGAGEMENT_PROFILES.md).

The repository safety checker (`vapt-verify security scan`) treats everything
under `profiles/examples/` as a sanitized area and will fail if a
non-documentation IP address appears here.
