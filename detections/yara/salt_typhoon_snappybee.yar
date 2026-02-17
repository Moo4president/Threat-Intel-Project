/*
    Salt Typhoon (Earth Estries) - YARA Detection Rules
    
    Author:      Moo
    Created:     2026-02-17
    Version:     1.0
    Description: Two detection rules for Salt Typhoon APT malware and artifacts.
                 Rule 1 combines hash-based and behavioral detection for SNAPPYBEE.
                 Rule 2 detects Cisco router exploitation artifacts (TTP-based).
    
    Sources:
        [1] CISA Advisory AA25-239A (August 2025)
        [2] Trend Micro - "Game of Emperor: Earth Estries" (November 2024)
        [3] Darktrace - "Salty Much: Salt Typhoon intrusion" (October 2025)
        [4] Rapid7 - "Salt Typhoon: Threat Assessment" (August 2025)
    
    NOTE: These rules are IOC-based, derived from published threat intelligence
    rather than binary samples. For production deployment, validate against your
    environment's baseline to tune false positives.

    License: MIT
*/


import "hash"


// =============================================================================
// RULE 1: SNAPPYBEE (Deed RAT) - Hash + Behavioral Detection
// Approach: High-confidence hash matching with behavioral fallback using
//           filename co-occurrence patterns from cross-source correlation.
// Sources: Trend Micro [2], Darktrace [3]
// =============================================================================

rule SaltTyphoon_SNAPPYBEE
{
    meta:
        description     = "Detects SNAPPYBEE (Deed RAT) loader and payload components used by Salt Typhoon via DLL sideloading against Norton, Bkav, and IObit AV products"
        author          = "Moo"
        date            = "2026-02-17"
        version         = "1.0"
        threat_actor    = "Salt Typhoon / Earth Estries"
        malware_family  = "SNAPPYBEE / Deed RAT"
        mitre_attack    = "T1574.002 - DLL Side-Loading, T1574.001 - DLL Search Order Hijacking, T1105 - Ingress Tool Transfer"
        reference_1     = "https://www.trendmicro.com/en_us/research/24/k/earth-estries.html"
        reference_2     = "https://www.darktrace.com/blog/salty-much-darktraces-view-on-a-recent-salt-typhoon-intrusion"
        severity        = "CRITICAL"
        
        // Trend Micro SHA-256 hashes (loaders)
        hash_1          = "fc3be6917fd37a083646ed4b97ebd2d45734a1e154e69c9c33ab00b0589a09e5"
        hash_2          = "25b9fdef3061c7dfea744830774ca0e289dba7c14be85f0d4695d382763b409b"
        hash_3          = "6d64643c044fe534dbb2c1158409138fcded757e550c6f79eada15e69a7865bc"
        hash_4          = "b2b617e62353a672626c13cc7ad81b27f23f91282aad7a3a0db471d84852a9ac"
        hash_5          = "05840de7fa648c41c60844c4e5d53dbb3bc2a5250dcb158a95b77bc0f68fa870"
        // Trend Micro SHA-256 hashes (encrypted payloads)
        hash_6          = "fba149eb5ef063bc6a2b15bd67132ea798919ed36c5acda46ee9b1118b823098"
        hash_7          = "1a38303fb392ccc5a88d236b4f97ed404a89c1617f34b96ed826e7bb7257e296"
        // Darktrace SHA-1
        hash_8_sha1     = "b5367820cd32640a2d5e4c3a3c1ceedbbb715be2"

    strings:
        // --- SNAPPYBEE loader DLL names (sideloaded via legitimate AV executables) ---
        // Cross-source validated: these filenames appear in BOTH Trend Micro and Darktrace
        $loader_1       = "WINMM.dll" ascii wide nocase
        $loader_2       = "DgApi.dll" ascii wide nocase
        $loader_3       = "imfsbDll.dll" ascii wide nocase
        $loader_4       = "fltLib.dll" ascii wide nocase
        
        // --- SNAPPYBEE encrypted payload files (masquerading as benign extensions) ---
        $payload_1      = "NortonLog.txt" ascii wide nocase
        $payload_2      = "dbindex.dat" ascii wide nocase
        $payload_3      = "Dialog.dat" ascii wide nocase
        
        // --- Sideloading host executables (legitimate AV binaries abused as hosts) ---
        $host_exe_1     = "imfsbSvc.exe" ascii wide nocase
        $host_exe_2     = "DisplayDialog.exe" ascii wide nocase
        $host_exe_3     = "pdc.exe" ascii wide nocase

        // --- C2 infrastructure embedded in samples ---
        $c2_ip_1        = "89.31.121.101" ascii wide
        $c2_ip_2        = "38.54.63.75" ascii wide
        $c2_ip_3        = "156.244.28.153" ascii wide
        $c2_domain      = "gandhibludtric.com" ascii wide nocase
        $c2_uri         = "/17ABE7F017ABE7F0" ascii wide

    condition:
        // --- TIER 1: Exact hash match (zero false positive) ---
        hash.sha256(0, filesize) == "fc3be6917fd37a083646ed4b97ebd2d45734a1e154e69c9c33ab00b0589a09e5" or
        hash.sha256(0, filesize) == "25b9fdef3061c7dfea744830774ca0e289dba7c14be85f0d4695d382763b409b" or
        hash.sha256(0, filesize) == "6d64643c044fe534dbb2c1158409138fcded757e550c6f79eada15e69a7865bc" or
        hash.sha256(0, filesize) == "b2b617e62353a672626c13cc7ad81b27f23f91282aad7a3a0db471d84852a9ac" or
        hash.sha256(0, filesize) == "05840de7fa648c41c60844c4e5d53dbb3bc2a5250dcb158a95b77bc0f68fa870" or
        hash.sha256(0, filesize) == "fba149eb5ef063bc6a2b15bd67132ea798919ed36c5acda46ee9b1118b823098" or
        hash.sha256(0, filesize) == "1a38303fb392ccc5a88d236b4f97ed404a89c1617f34b96ed826e7bb7257e296" or
        
        // --- TIER 2: Behavioral detection (catches variants) ---
        (
            filesize < 5MB and
            (
                // PE file with sideloading loader name + payload or C2 reference
                (
                    uint16(0) == 0x5A4D and
                    1 of ($loader_*) and
                    (1 of ($payload_*) or 1 of ($c2_*) or 1 of ($host_exe_*))
                ) or
                // Non-PE file (encrypted payload) with known payload filename + C2
                (
                    not (uint16(0) == 0x5A4D) and
                    1 of ($payload_*) and
                    1 of ($c2_*)
                ) or
                // Archive/memory dump containing both loader and payload artifacts
                (
                    2 of ($loader_*) and
                    1 of ($payload_*)
                )
            )
        )
}
