#!/usr/bin/env python3
"""Update ATT&CK Navigator layers from v18 to v19.

ATT&CK v19 (April 2026) split Defense Evasion (TA0005) into:
  - Stealth      (TA0005)  — hiding within normal-looking activity
  - Defense Impairment (TA0112) — actively breaking security controls

Steps performed:
  1. Fetch v19 enterprise-attack STIX bundle to build technique → tactic mapping.
  2. Re-download MITRE-provided Navigator layers for software/mitigations.
     Falls back to in-place tactic remap if a download fails.
  3. Remap "defense-evasion" tactic in all custom/derived layers in place.
  4. Rebuild cumulated_black_basta_ttps.json from its 5 source layers.
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent

# MITRE-provided layers to re-download (relative to BASE_DIR)
MITRE_DOWNLOADS = {
    "red/S1070-BlackBasta-enterprise-layer.json":
        "https://attack.mitre.org/software/S1070/S1070-enterprise-layer.json",
    "red/S0002-Mimikatz-enterprise-layer.json":
        "https://attack.mitre.org/software/S0002/S0002-enterprise-layer.json",
    "red/S0029-PsExec-enterprise-layer.json":
        "https://attack.mitre.org/software/S0029/S0029-enterprise-layer.json",
    "red/S0154-CobaltStrike-enterprise-layer.json":
        "https://attack.mitre.org/software/S0154/S0154-enterprise-layer.json",
    "red/S0190-BITSAdmin-enterprise-layer.json":
        "https://attack.mitre.org/software/S0190/S0190-enterprise-layer.json",
    "red/S0650-QakBot-enterprise-layer.json":
        "https://attack.mitre.org/software/S0650/S0650-enterprise-layer.json",
    "red/S1040-Rclone-enterprise-layer.json":
        "https://attack.mitre.org/software/S1040/S1040-enterprise-layer.json",
    "blue/M1049-enterprise-layer.json":
        "https://attack.mitre.org/mitigations/M1049/M1049-enterprise-layer.json",
}

# Custom / derived layers that need in-place tactic remapping
IN_PLACE_FILES = [
    "red/CISA_2024_AA24-131A-enterprise-layer.json",
    "blue/sysmon-modular.json",
    "blue/cumulated_detections_and_preventions.json",
    "purple/black_basta_detection_coverage.json",
    "purple/configured_vs_triggered.json",
]

# Sources that make up cumulated_black_basta_ttps.json (after re-download)
CUMULATED_SOURCES = [
    "red/CISA_2024_AA24-131A-enterprise-layer.json",
    "red/S0190-BITSAdmin-enterprise-layer.json",
    "red/S1070-BlackBasta-enterprise-layer.json",
    "red/S1040-Rclone-enterprise-layer.json",
    "red/S0029-PsExec-enterprise-layer.json",
]

# IDs of the two successor tactics that replaced Defense Evasion
SUCCESSOR_TACTIC_IDS = {"TA0005", "TA0112"}


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def fetch_json(url: str) -> dict:
    print(f"    GET {url}")
    result = subprocess.run(
        ["curl", "-fsSL", "--max-time", "60", "-A", "purple-team-workshop/update-v19", url],
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Step 1: Build v19 tactic mapping from STIX
# ---------------------------------------------------------------------------

def load_v19_stix() -> dict:
    """Return the raw v19 enterprise-attack STIX bundle."""
    urls = [
        "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v19.0/enterprise-attack/enterprise-attack.json",
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    ]
    for url in urls:
        try:
            data = fetch_json(url)
            print(f"  Loaded STIX bundle ({len(data.get('objects', []))} objects)")
            return data
        except Exception as exc:
            print(f"  Warning: {url} — {exc}")
    sys.exit("ERROR: Could not fetch v19 STIX data from any URL")


def get_successor_slugs(stix: dict) -> set[str]:
    """Return the phase_name slugs for TA0005 and TA0112 in v19."""
    slugs: set[str] = set()
    for obj in stix.get("objects", []):
        if obj.get("type") != "x-mitre-tactic":
            continue
        for ref in obj.get("external_references", []):
            if (
                ref.get("source_name") == "mitre-attack"
                and ref.get("external_id") in SUCCESSOR_TACTIC_IDS
            ):
                slug = obj.get("x_mitre_shortname", "")
                if slug:
                    slugs.add(slug)
    return slugs


def build_tactic_map(stix: dict) -> dict[str, list[str]]:
    """Return {technique_id: [tactic_phase_names]} for all v19 techniques."""
    mapping: dict[str, list[str]] = {}
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        ext_id = next(
            (r["external_id"]
             for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext_id:
            continue
        tactics = [
            kc["phase_name"]
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == "mitre-attack"
        ]
        mapping[ext_id] = tactics
    return mapping


# ---------------------------------------------------------------------------
# Step 2: Re-download MITRE source layers
# ---------------------------------------------------------------------------

def download_mitre_layers(tactic_map: dict, successor_slugs: set[str]) -> None:
    print("\n--- Re-downloading MITRE source layers ---")
    for rel_path, url in MITRE_DOWNLOADS.items():
        dest = BASE_DIR / rel_path
        print(f"\n  {rel_path}")
        try:
            data = fetch_json(url)
            with open(dest, "w") as fh:
                json.dump(data, fh, indent=2)
                fh.write("\n")
            print(f"  Saved.")
        except Exception as exc:
            print(f"  Download failed ({exc}). Falling back to in-place update.")
            _remap_file(dest, tactic_map, successor_slugs)


# ---------------------------------------------------------------------------
# Step 3: In-place tactic remap helpers
# ---------------------------------------------------------------------------

def _remap_entry(
    entry: dict,
    tactic_map: dict,
    successor_slugs: set[str],
) -> list[dict]:
    """Remap a single technique entry.

    If the entry's tactic is not "defense-evasion", return it unchanged.
    Otherwise replace it with entries for the correct successor tactic(s).
    """
    if entry.get("tactic") != "defense-evasion":
        return [entry]

    tech_id = entry.get("techniqueID", "")
    v19_tactics = tactic_map.get(tech_id, [])

    # Keep only the successor tactics (stealth / defense-impairment)
    new_tactics = [t for t in v19_tactics if t in successor_slugs]

    if not new_tactics:
        if v19_tactics:
            # Technique is still in v19 but no longer under a defense-evasion successor
            print(f"    {tech_id}: defense-evasion removed entirely in v19 "
                  f"(now in {v19_tactics}) — dropping entry")
        else:
            print(f"    {tech_id}: not found in v19 STIX (deprecated?) — dropping entry")
        return []

    result = []
    for tactic in new_tactics:
        new_entry = copy.deepcopy(entry)
        new_entry["tactic"] = tactic
        result.append(new_entry)

    label = " + ".join(new_tactics)
    print(f"    {tech_id}: defense-evasion → {label}")
    return result


def _remap_file(
    path: Path,
    tactic_map: dict,
    successor_slugs: set[str],
) -> None:
    """Load a Navigator layer, remap defense-evasion entries, write back."""
    with open(path) as fh:
        layer = json.load(fh)

    new_techniques: list[dict] = []
    changed = 0
    for entry in layer.get("techniques", []):
        remapped = _remap_entry(entry, tactic_map, successor_slugs)
        new_techniques.extend(remapped)
        original_tactic = entry.get("tactic")
        if (
            len(remapped) != 1
            or (remapped and remapped[0].get("tactic") != original_tactic)
        ):
            changed += 1

    layer["techniques"] = new_techniques

    # Update ATT&CK version in layers that use the standard versions block
    if isinstance(layer.get("versions"), dict):
        layer["versions"]["attack"] = "19"

    with open(path, "w") as fh:
        json.dump(layer, fh, indent=2)
        fh.write("\n")

    print(f"    {changed} defense-evasion entries remapped, "
          f"{len(new_techniques)} total technique entries")


def update_in_place(tactic_map: dict, successor_slugs: set[str]) -> None:
    print("\n--- Remapping in-place layers ---")
    for rel_path in IN_PLACE_FILES:
        path = BASE_DIR / rel_path
        print(f"\n  {rel_path}")
        _remap_file(path, tactic_map, successor_slugs)


# ---------------------------------------------------------------------------
# Step 4: Rebuild cumulated_black_basta_ttps.json
# ---------------------------------------------------------------------------

def rebuild_cumulated(tactic_map: dict, successor_slugs: set[str]) -> None:
    print("\n--- Rebuilding cumulated_black_basta_ttps.json ---")

    # Collect (techniqueID, tactic) pairs enabled in any source layer
    enabled: set[tuple[str, str]] = set()
    for rel_path in CUMULATED_SOURCES:
        path = BASE_DIR / rel_path
        with open(path) as fh:
            layer = json.load(fh)
        for entry in layer.get("techniques", []):
            # Navigator convention: absent "enabled" means enabled=true
            if entry.get("enabled", True):
                tech_id = entry.get("techniqueID", "")
                tactic = entry.get("tactic", "")
                if tech_id and tactic:
                    enabled.add((tech_id, tactic))

    print(f"  {len(enabled)} (techniqueID, tactic) pairs enabled across sources")

    # Load the existing cumulated layer as the baseline
    cumulated_path = BASE_DIR / "red/cumulated_black_basta_ttps.json"
    with open(cumulated_path) as fh:
        cumulated = json.load(fh)

    # Rebuild the techniques list:
    #   - remap any defense-evasion entries
    #   - set enabled/score based on the source union
    seen: set[tuple[str, str]] = set()
    new_techniques: list[dict] = []
    enabled_count = 0

    for entry in cumulated.get("techniques", []):
        tech_id = entry.get("techniqueID", "")
        remapped = _remap_entry(entry, tactic_map, successor_slugs)

        for new_entry in remapped:
            tactic = new_entry.get("tactic", "")
            key = (tech_id, tactic)
            if key in seen:
                continue
            seen.add(key)

            if key in enabled:
                new_entry["enabled"] = True
                new_entry["score"] = 1
                enabled_count += 1
            else:
                new_entry["enabled"] = False
                new_entry.pop("score", None)

            new_techniques.append(new_entry)

    cumulated["techniques"] = new_techniques
    if isinstance(cumulated.get("versions"), dict):
        cumulated["versions"]["attack"] = "19"

    with open(cumulated_path, "w") as fh:
        json.dump(cumulated, fh, indent=2)
        fh.write("\n")

    print(f"  Wrote {len(new_techniques)} entries "
          f"({enabled_count} enabled) to cumulated_black_basta_ttps.json")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== ATT&CK v19 update ===\n")

    print("Step 1: Fetching v19 STIX data")
    stix = load_v19_stix()

    successor_slugs = get_successor_slugs(stix)
    if not successor_slugs:
        sys.exit(
            "ERROR: Could not find successor tactic slugs for TA0005/TA0112 in STIX. "
            "Check that the STIX bundle is v19."
        )
    print(f"  Defense Evasion successors: {sorted(successor_slugs)}")

    tactic_map = build_tactic_map(stix)
    de_techniques = [t for t, tactics in tactic_map.items()
                     if any(s in tactics for s in successor_slugs)]
    print(f"  Techniques now under successor tactics: {len(de_techniques)}")

    # Sanity check: defense-evasion should be gone
    residual = [t for t, tactics in tactic_map.items() if "defense-evasion" in tactics]
    if residual:
        print(f"  WARNING: {len(residual)} techniques still have 'defense-evasion' in v19 "
              f"STIX — the bundle may not be v19.")

    print("\nStep 2: Re-downloading MITRE source layers")
    download_mitre_layers(tactic_map, successor_slugs)

    print("\nStep 3: Remapping in-place layers")
    update_in_place(tactic_map, successor_slugs)

    print("\nStep 4: Rebuilding cumulated layer")
    rebuild_cumulated(tactic_map, successor_slugs)

    print("\n=== Done ===")
    print("\nVerification commands:")
    print('  grep -r \'"defense-evasion"\' resources/cti/ | wc -l   # expect 0')
    print('  grep -rh \'"tactic"\' resources/cti/*.json resources/cti/**/*.json '
          '| sort -u                                               # expect no defense-evasion')


if __name__ == "__main__":
    main()
