# IOC Sources & Analytical Context

This folder contains indicators of compromise (IOCs) from three independent sources tracking Salt Typhoon activity. Each source was selected because it captures a different operational layer of the threat actor's campaigns — together, they provide a more complete picture than any single feed.

## Sources

**CISA / NSA / FBI Joint Advisory AA25-239A** (August 2025)
`AA25-239A_salt_typhoon_stix.json`
Covers Salt Typhoon's network infrastructure campaign targeting U.S. and allied telecommunications providers. Contains 87 IP addresses observed between August 2021 and June 2025, primarily associated with compromised routers, VPS staging nodes, and lateral movement across ISP backbone networks. Published in STIX 2.1 format for direct ingestion into threat intelligence platforms such as MISP or OpenCTI.
Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a

**Trend Micro — Earth Estries IOC List** (October 2024)
`IOC_list-EarthEstries.txt`
Covers the endpoint malware layer of Salt Typhoon operations, primarily targeting government and telecom entities in Southeast Asia. Contains 10 SHA-256 file hashes for SNAPPYBEE loaders/payloads and DEMODEX rootkit components, 22 C2 IP addresses, and 16 C2 domains — organized by Campaign Alpha and Campaign Beta. Published as a plain text reference alongside Trend Micro's "Game of Emperor" research report.
Source: https://www.trendmicro.com/en_us/research/24/k/breaking-down-earth-estries-persistent-ttps-in-prolonged-cyber-o.html

**Darktrace — Salt Typhoon European Telco Intrusion** (October 2025)
`darktrace_salt_typhoon_iocs.txt`
Covers a July 2025 intrusion against a European telecommunications organization. Documents exploitation of CVE-2025-5777 (Citrix NetScaler Gateway), DLL sideloading via legitimate antivirus binaries to deliver SNAPPYBEE, and C2 communications over LightNode VPS infrastructure. Provides a small but high-confidence indicator set from a directly observed incident.
Source: https://www.darktrace.com/blog/salty-much-darktraces-view-on-a-recent-salt-typhoon-intrusion

## Why These Three Sources Matter Together

Cross-referencing these datasets reveals near-zero overlap: only a single IP address (`45.125.67.144`) appears in both the CISA and Trend Micro collections. No hashes and no domains are shared between any of the three sources.

This is not a gap in collection — it reflects how Salt Typhoon actually operates. The group functions as multiple sub-teams with compartmentalized infrastructure. CISA documents the network-layer campaign targeting routers and ISP interconnections. Trend Micro documents the endpoint-layer campaign deploying custom malware inside enterprise environments. Darktrace documents a mid-2025 intrusion using yet another distinct C2 setup. Three sources, three geographic regions (North America, Southeast Asia, Europe), three operational perspectives on the same threat actor.

For defenders, the implication is clear: blocking IOCs from a single vendor's feed provides incomplete coverage. Effective detection against Salt Typhoon requires layering network-level indicators, endpoint-level signatures, and behavioral analytics — because the group itself operates in layers.

## Additional Commercial Sources

Organizations with access to commercial threat intelligence platforms should also consult **Silent Push's IOFA (Indicators of Future Attack) feeds**, which identified 45+ previously unreported Salt Typhoon domains as of September 2025 through infrastructure pattern analysis. These feeds require an enterprise subscription and are not included here, but provide pre-weaponization detection of emerging Salt Typhoon infrastructure. See: https://www.silentpush.com/blog/salt-typhoon-2025/
