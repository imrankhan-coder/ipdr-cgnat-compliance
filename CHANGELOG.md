# Changelog

All notable changes to the IPDR CGNAT Compliance & LEA platform are documented
here. This project adheres to a simplified [Semantic Versioning](https://semver.org/)
scheme.

## [3.0.0] — 2026-07

A large feature release focused on operational accuracy, multi-router support,
and law-enforcement query hardening. Highlights: honest CGNAT accounting on
real conntrack metrics, RouterOS version auto-detection, subscriber footprint
attribution, LEA query hardening, static-ARP infrastructure inventory, and an
optional bogon-leak mitigation workflow.

### Added
- **NAT Pool Status — real conntrack metrics.** Pool utilization is now computed
  from live router connection-tracking data (per public IP: distinct
  translated ports and active connections) instead of cumulative log-row
  counts. This corrects impossible >100% utilization readings for dynamic-NAPT
  routers, where source ports are shared across destinations. A two-tier poller
  captures box-wide conntrack every 60s and per-pool detail every 10 minutes.
- **Subscriber footprint.** The username lookup gains a court-defensible
  footprint view: traffic is grouped by public IP with an honest **distinct
  port count** (never a synthetic port range, which would falsely imply unused
  ports were in use), plus time window, flow count, and drill-down to the exact
  (public IP, port, destination, timestamp) rows. Includes a universal
  typeahead search across username, CGN IP, public IP, and MAC.
- **RouterOS version auto-detection.** Each API-enabled router's RouterOS
  version is detected on every poll and stored, so the platform adapts its log
  parsing to the router's major version and automatically picks up in-place
  upgrades (e.g. v6 → v7) without manual reconfiguration.
- **Static-ARP infrastructure inventory.** Statically addressed infrastructure
  (OLTs, switches, radios, media servers) that never appears in DHCP leases is
  now polled from the router ARP table, classified (excluding WAN uplinks and
  DHCP-learned entries), and shown in a searchable, interface-filtered
  "Static ARP" view. Only entries with a resolved MAC are tracked, excluding
  unresolved phantom ARP.
- **Bogon-leak mitigation (optional, per-NAS).** An opt-in workflow to identify
  subscriber traffic leaking to non-existent private/bogon destinations (a
  common cause of NAT-table exhaustion), with a safety check that cross-
  references destinations against known infrastructure before any drop. The
  platform provides visibility and status only; the router firewall
  configuration is applied manually by the operator. Live status
  (Protected / Partial / Not-deployed / Off) is detected read-only via the API
  and cached for instant display.
- **NAS purge-on-delete.** Removing a NAS now purges all of its associated data
  across every table — including large partitioned translation tables and
  per-router metrics tables that lack a foreign-key cascade — preventing
  orphaned rows attributed to a device that no longer exists.

### Changed
- **LEA query — hardened.** The IP + port + timestamp lookup now:
  - always renders a clean "no match found" result instead of erroring when a
    query has no matching translation;
  - relabels the port field to **"Public Port"** (the translated source port on
    the public IP), with guidance clarifying it is not the destination service
    port — preventing incorrect lookups;
  - adds a selectable **search window** (±1 min to ±1 hour) for cases where the
    request timestamp is approximate, while still surfacing port-reuse
    collisions so an exact time can disambiguate;
  - records the search window used in the audit trail, so every query's full
    parameters (IP, port, time, window, case reference, reason) are logged.

### Fixed
- Corrected NAT pool utilization that could read far above 100% on
  dynamic-NAPT routers.
- Fixed orphaned per-router rows left behind when a NAS was deleted.
- Fixed a 500 error on the LEA page when a MikroTik-only deployment had no
  matching translation for a queried IP:port:time.

### Notes
- This release remains a reference implementation. See DISCLAIMER.md and
  SECURITY.md. All example addresses use RFC 5737 / RFC 6598 ranges and all
  identifiers are illustrative.

## [2.0.0] — 2026-07

Initial public release.

### Added
- CGNAT translation ingestion (per-connection syslog model) with a
  version-tolerant parser.
- DHCP lease tracking and live session views.
- LEA request parsing across multiple common request formats.
- Subscriber enrichment (customer name / MAC) via router API.
- Role-based access, audit logging, and a compliance-oriented LEA query page.
- Deterministic-NAT (port-block) support alongside the per-connection model.
