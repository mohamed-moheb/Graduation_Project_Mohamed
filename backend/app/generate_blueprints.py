import os
import json
import re
import argparse
import requests
from pathlib import Path
from typing import Dict, List, Optional

try:
    from mitreattack.stix20 import MitreAttackData
except ImportError:
    MitreAttackData = None

try:
    import anthropic
except ImportError:
    anthropic = None


# ── Wazuh field schema ────────────────────────────────────────────────────────
# Maps generic detection concepts to Wazuh-compatible field names.
# Based on Wazuh documentation for Sysmon/Windows event log decoders.
WAZUH_FIELD_MAP = {
    "process.name":        "win.eventdata.image",
    "process.command":     "win.eventdata.commandLine",
    "process.parent":      "win.eventdata.parentImage",
    "network.dst_port":    "win.eventdata.destinationPort",
    "network.dst_ip":      "win.eventdata.destinationIp",
    "file.path":           "win.eventdata.targetFilename",
    "registry.path":       "win.eventdata.targetObject",
    "registry.value":      "win.eventdata.details",
    "dns.query":           "win.eventdata.queryName",
}

# Maps logsource keywords found in Sigma rules to Wazuh logsource tuples
LOGSOURCE_MAP = {
    "process_creation":  ("windows", "process_creation"),
    "network_connection": ("windows", "network_connection"),
    "file_event":        ("windows", "file_event"),
    "registry_event":    ("windows", "registry_event"),
    "dns_query":         ("windows", "dns_query"),
    "image_load":        ("windows", "image_load"),
}

# ── Known high-quality hand-crafted overrides ─────────────────────────────────
# These are kept from the original blueprints.py for techniques where
# ATT&CK detection text is too vague and auto-generation produces weak rules.
# The generator will prefer these over auto-generated entries.
MANUAL_OVERRIDES = {
    "T1059.001": [
        {"name": "PowerShell encoded command", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"),
                        ("win.eventdata.commandLine", "contains", "-enc")]},
        {"name": "PowerShell download cradle", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"),
                        ("win.eventdata.commandLine", "contains", "DownloadString")]},
        {"name": "PowerShell IEX in-memory", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "powershell.exe"),
                        ("win.eventdata.commandLine", "contains", "IEX")]},
    ],
    "T1003.001": [
        {"name": "LSASS access via command line", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "lsass")]},
        {"name": "Mimikatz sekurlsa module", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.commandLine", "contains", "sekurlsa")]},
    ],
    "T1547.001": [
        {"name": "Registry Run key persistence", "logsource": ("windows", "registry_event"),
         "conditions": [("win.eventdata.targetObject", "contains", "CurrentVersion\\Run")]},
    ],
    "T1071.001": [
        {"name": "Outbound HTTPS from PowerShell", "logsource": ("windows", "network_connection"),
         "conditions": [("win.eventdata.destinationPort", "equals", "443"),
                        ("win.eventdata.image", "endswith", "powershell.exe")]},
    ],
    "T1053.005": [
        {"name": "Scheduled task creation via schtasks", "logsource": ("windows", "process_creation"),
         "conditions": [("win.eventdata.image", "endswith", "schtasks.exe"),
                        ("win.eventdata.commandLine", "contains", "/create")]},
    ],
}


# ── Source 1: MITRE ATT&CK STIX bundle ───────────────────────────────────────

def load_attack_techniques(stix_path: str) -> Dict[str, dict]:
    """
    Load all non-revoked techniques from the ATT&CK enterprise STIX bundle.
    Returns a dict of {technique_id: {name, description, detection, tactics}}.
    """
    if MitreAttackData is None:
        raise ImportError("mitreattack-python is required: pip install mitreattack-python")

    print("Loading ATT&CK STIX bundle...")
    attack_data = MitreAttackData(stix_path)
    techniques = attack_data.get_techniques(remove_revoked_deprecated=True)

    result = {}
    for t in techniques:
        refs = t.get("external_references", [])
        tid = next((r.get("external_id", "") for r in refs
                    if r.get("source_name") == "mitre-attack"), "")
        if not tid:
            continue

        kill_chain = t.get("kill_chain_phases", [])
        tactics = [k.get("phase_name", "") for k in kill_chain]

        result[tid] = {
            "name":      t.get("name", ""),
            "detection": t.get("x_mitre_detection", ""),
            "tactics":   tactics,
        }

    print(f"  Loaded {len(result)} techniques from ATT&CK STIX bundle.")
    return result


# ── Source 2: Sigma Rules ─────────────────────────────────────────────────────

def load_sigma_rules(sigma_dir: str) -> Dict[str, List[dict]]:
    """
    Scan a local Sigma rules directory for YAML files.
    Extract logsource and detection conditions, index by ATT&CK technique ID.
    Returns {technique_id: [rule_dict, ...]}.
    """
    sigma_map: Dict[str, List[dict]] = {}
    sigma_path = Path(sigma_dir)

    if not sigma_path.exists():
        print(f"  Sigma directory not found at {sigma_dir}, skipping.")
        return sigma_map

    # Try yaml import
    try:
        import yaml
    except ImportError:
        print("  PyYAML not installed, skipping Sigma rules. pip install pyyaml")
        return sigma_map

    yaml_files = list(sigma_path.rglob("*.yml"))
    print(f"  Scanning {len(yaml_files)} Sigma rule files...")

    for fpath in yaml_files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except Exception:
            continue

        if not isinstance(rule, dict):
            continue

        # Extract ATT&CK technique IDs from tags
        tags = rule.get("tags", [])
        tids = [t.replace("attack.", "").upper()
                for t in tags
                if t.startswith("attack.t") or t.startswith("attack.T")]
        if not tids:
            continue

        # Extract logsource
        ls = rule.get("logsource", {})
        product  = ls.get("product", "windows")
        category = ls.get("category", "process_creation")
        logsource = LOGSOURCE_MAP.get(category, ("windows", category))

        # Extract detection conditions
        detection = rule.get("detection", {})
        conditions = _parse_sigma_detection(detection)
        if not conditions:
            continue

        rule_entry = {
            "name":       rule.get("title", f"Sigma rule from {fpath.name}"),
            "logsource":  logsource,
            "conditions": conditions,
        }

        for tid in tids:
            sigma_map.setdefault(tid, []).append(rule_entry)

    total = sum(len(v) for v in sigma_map.values())
    print(f"  Extracted {total} Sigma rule entries across {len(sigma_map)} techniques.")
    return sigma_map


def _parse_sigma_detection(detection: dict) -> List[tuple]:
    """
    Convert a Sigma detection block into a list of (field, operator, value) tuples
    compatible with the TECHNIQUE_BLUEPRINTS format.
    """
    conditions = []
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(value, dict):
            for field, match in value.items():
                wazuh_field = WAZUH_FIELD_MAP.get(field, field)
                if isinstance(match, str):
                    op = "endswith" if match.startswith("*") else \
                         "startswith" if match.endswith("*") else "contains"
                    val = match.strip("*")
                    conditions.append((wazuh_field, op, val))
                elif isinstance(match, list):
                    for m in match[:2]:  # take first 2 to avoid over-specificity
                        if isinstance(m, str):
                            op = "contains"
                            conditions.append((wazuh_field, op, m.strip("*")))
    return conditions[:4]  # cap at 4 conditions per rule


# ── Source 3: Elastic Detection Rules (GitHub API) ───────────────────────────

def fetch_elastic_rules(limit: int = 300) -> Dict[str, List[dict]]:
    """
    Fetch Elastic detection rules from the elastic/detection-rules GitHub repo.
    Parses TOML rule files that reference ATT&CK technique IDs.
    Returns {technique_id: [rule_dict, ...]}.
    """
    elastic_map: Dict[str, List[dict]] = {}

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            print("  tomllib/tomli not available, skipping Elastic rules. pip install tomli")
            return elastic_map

    print("  Fetching Elastic detection rules index from GitHub...")
    api_url = (
        "https://api.github.com/repos/elastic/detection-rules"
        "/git/trees/main?recursive=1"
    )
    try:
        resp = requests.get(api_url, timeout=15)
        resp.raise_for_status()
        tree = resp.json().get("tree", [])
    except Exception as e:
        print(f"  Could not fetch Elastic rules index: {e}")
        return elastic_map

    toml_paths = [
        item["path"] for item in tree
        if item["path"].startswith("rules/") and item["path"].endswith(".toml")
    ][:limit]

    print(f"  Fetching {len(toml_paths)} Elastic rule files...")
    base_raw = "https://raw.githubusercontent.com/elastic/detection-rules/main/"
    fetched = 0

    for path in toml_paths:
        try:
            r = requests.get(base_raw + path, timeout=10)
            if r.status_code != 200:
                continue
            rule = tomllib.loads(r.text)
        except Exception:
            continue

        metadata = rule.get("metadata", {})
        rule_data = rule.get("rule", {})

        # Extract ATT&CK IDs
        threat = rule_data.get("threat", [])
        tids = []
        for t in threat:
            for tech in t.get("technique", []):
                tid = tech.get("id", "")
                if tid:
                    tids.append(tid.upper())
                for sub in tech.get("subtechnique", []):
                    sid = sub.get("id", "")
                    if sid:
                        tids.append(sid.upper())

        if not tids:
            continue

        # Extract query / EQL conditions
        query = rule_data.get("query", "") or rule_data.get("language", "")
        conditions = _parse_elastic_query(query)
        if not conditions:
            continue

        rule_entry = {
            "name":       rule_data.get("name", path.split("/")[-1]),
            "logsource":  ("windows", "process_creation"),
            "conditions": conditions,
        }

        for tid in tids:
            elastic_map.setdefault(tid, []).append(rule_entry)

        fetched += 1

    total = sum(len(v) for v in elastic_map.values())
    print(f"  Extracted {total} Elastic rule entries across {len(elastic_map)} techniques.")
    return elastic_map


def _parse_elastic_query(query: str) -> List[tuple]:
    """
    Extract simple field:value conditions from Elastic EQL/KQL query strings.
    """
    conditions = []
    if not query:
        return conditions

    # Match patterns like: process.name : "powershell.exe"
    # or process.command_line like~ "*-enc*"
    pattern = re.findall(
        r'([\w.]+)\s*(?:like~|:)\s*["\']?([^"\')\s,]+)["\']?',
        query
    )
    for field, value in pattern[:3]:
        wazuh_field = WAZUH_FIELD_MAP.get(field, None)
        if wazuh_field:
            value = value.strip("*")
            op = "contains" if "*" in value else "endswith" if not value.startswith("/") else "contains"
            conditions.append((wazuh_field, op, value))

    return conditions


# ── Source 4: LLM conversion of ATT&CK detection text ────────────────────────

def llm_convert_detection_text(
    tid: str,
    technique_name: str,
    detection_text: str,
    tactics: List[str],
    api_key: Optional[str] = None,
) -> List[dict]:
    """
    Use the Anthropic Claude API to convert ATT&CK detection notes into
    structured Wazuh blueprint rule templates.
    Falls back to a heuristic extractor if no API key is available.
    """
    if not detection_text.strip():
        return []

    if anthropic is None or not api_key:
        return _heuristic_detection_to_blueprint(tid, detection_text)

    client = anthropic.Anthropic(api_key=api_key)

    prompt = f"""You are a detection engineering expert converting MITRE ATT&CK detection guidance into Wazuh SIEM rule templates.

Technique: {tid} — {technique_name}
Tactics: {', '.join(tactics)}
ATT&CK Detection Notes:
{detection_text}

Convert the detection guidance above into 1-3 Wazuh detection rule templates.
Return ONLY a valid JSON array. Each element must have exactly these fields:
- "name": short description of what is detected (string)
- "logsource": array of two strings [product, category] e.g. ["windows", "process_creation"]
  Valid categories: process_creation, network_connection, file_event, registry_event, dns_query
- "conditions": array of [field, operator, value] triples
  Valid fields (Wazuh): win.eventdata.image, win.eventdata.commandLine, win.eventdata.parentImage,
  win.eventdata.destinationPort, win.eventdata.destinationIp, win.eventdata.targetFilename,
  win.eventdata.targetObject, win.eventdata.details, win.eventdata.queryName
  Valid operators: contains, endswith, startswith, equals

Example output:
[
  {{
    "name": "Suspicious PowerShell execution",
    "logsource": ["windows", "process_creation"],
    "conditions": [
      ["win.eventdata.image", "endswith", "powershell.exe"],
      ["win.eventdata.commandLine", "contains", "-enc"]
    ]
  }}
]

Return ONLY the JSON array, no explanation, no markdown."""

    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = message.content[0].text.strip()
        # Strip markdown fences if present
        raw = re.sub(r"```(?:json)?", "", raw).strip("`").strip()
        rules = json.loads(raw)
        if not isinstance(rules, list):
            return []

        result = []
        for r in rules:
            if not all(k in r for k in ("name", "logsource", "conditions")):
                continue
            ls = r["logsource"]
            conds = [tuple(c) for c in r["conditions"] if len(c) == 3]
            if conds:
                result.append({
                    "name":       r["name"],
                    "logsource":  tuple(ls),
                    "conditions": conds,
                })
        return result

    except Exception as e:
        print(f"    LLM conversion failed for {tid}: {e}")
        return _heuristic_detection_to_blueprint(tid, detection_text)


def _heuristic_detection_to_blueprint(tid: str, detection_text: str) -> List[dict]:
    """
    Fallback: extract detection hints from ATT&CK detection text using
    keyword matching when no LLM API key is available.
    """
    text = detection_text.lower()
    rules = []

    # Process creation hints
    proc_keywords = {
        "powershell": ("win.eventdata.image", "endswith", "powershell.exe"),
        "cmd.exe":    ("win.eventdata.image", "endswith", "cmd.exe"),
        "wmic":       ("win.eventdata.image", "endswith", "wmic.exe"),
        "schtasks":   ("win.eventdata.image", "endswith", "schtasks.exe"),
        "rundll32":   ("win.eventdata.image", "endswith", "rundll32.exe"),
        "regsvr32":   ("win.eventdata.image", "endswith", "regsvr32.exe"),
        "certutil":   ("win.eventdata.image", "endswith", "certutil.exe"),
        "mshta":      ("win.eventdata.image", "endswith", "mshta.exe"),
        "net.exe":    ("win.eventdata.image", "endswith", "net.exe"),
    }

    for keyword, condition in proc_keywords.items():
        if keyword in text:
            rules.append({
                "name":       f"{tid} detection via {keyword}",
                "logsource":  ("windows", "process_creation"),
                "conditions": [condition],
            })
            break

    # Network connection hints
    if any(k in text for k in ["network", "connection", "port", "beacon", "c2", "command and control"]):
        rules.append({
            "name":       f"{tid} — suspicious outbound network connection",
            "logsource":  ("windows", "network_connection"),
            "conditions": [("win.eventdata.destinationPort", "equals", "443")],
        })

    # Registry hints
    if "registry" in text:
        rules.append({
            "name":       f"{tid} — registry modification",
            "logsource":  ("windows", "registry_event"),
            "conditions": [("win.eventdata.targetObject", "contains", "CurrentVersion")],
        })

    return rules[:2]


# ── Blueprint assembler ───────────────────────────────────────────────────────

def assemble_blueprints(
    attack_techniques: Dict[str, dict],
    sigma_rules: Dict[str, List[dict]],
    elastic_rules: Dict[str, List[dict]],
    anthropic_api_key: Optional[str] = None,
    max_rules_per_technique: int = 4,
) -> Dict[str, List[dict]]:
    """
    Merge all four sources into a single TECHNIQUE_BLUEPRINTS dictionary.

    Priority order (highest to lowest):
      1. Manual overrides (hand-crafted, validated)
      2. Sigma rules (community-validated, field-mapped)
      3. Elastic rules (cross-validation)
      4. LLM-converted ATT&CK detection text (auto-generated)
    """
    blueprints: Dict[str, List[dict]] = {}
    all_tids = set(attack_techniques.keys()) | set(sigma_rules.keys()) | set(elastic_rules.keys())

    print(f"\nAssembling blueprints for {len(all_tids)} techniques...")

    for tid in sorted(all_tids):
        rules = []

        # Priority 1: manual overrides
        if tid in MANUAL_OVERRIDES:
            blueprints[tid] = MANUAL_OVERRIDES[tid]
            continue

        # Priority 2: Sigma rules
        if tid in sigma_rules:
            rules.extend(sigma_rules[tid])

        # Priority 3: Elastic rules (add if not duplicate)
        if tid in elastic_rules:
            existing_names = {r["name"] for r in rules}
            for r in elastic_rules[tid]:
                if r["name"] not in existing_names:
                    rules.append(r)

        # Priority 4: LLM conversion of ATT&CK detection text
        if tid in attack_techniques and len(rules) < 2:
            tech = attack_techniques[tid]
            llm_rules = llm_convert_detection_text(
                tid,
                tech["name"],
                tech["detection"],
                tech["tactics"],
                api_key=anthropic_api_key,
            )
            for r in llm_rules:
                if r not in rules:
                    rules.append(r)

        # Deduplicate by condition fingerprint
        seen = set()
        deduped = []
        for r in rules:
            fp = str(sorted(r.get("conditions", [])))
            if fp not in seen:
                seen.add(fp)
                deduped.append(r)

        if deduped:
            blueprints[tid] = deduped[:max_rules_per_technique]

    print(f"Blueprint assembly complete: {len(blueprints)} techniques covered.")
    return blueprints


# ── Output writer ─────────────────────────────────────────────────────────────

def write_blueprints_file(blueprints: Dict[str, List[dict]], output_path: str):
    """
    Write the assembled blueprints to a Python file that can be
    imported directly as blueprints_generated.py.
    """
    lines = [
        '"""',
        'blueprints_generated.py',
        'Auto-generated by generate_blueprints.py',
        'Sources: MITRE ATT&CK STIX bundle, Sigma Rules, Elastic Detection Rules,',
        '         LLM conversion of ATT&CK detection notes (Claude API)',
        'Manual overrides applied for high-priority techniques.',
        '"""',
        'from typing import Dict, List',
        '',
        'TECHNIQUE_BLUEPRINTS: Dict[str, List[Dict]] = {',
    ]

    for tid, rules in sorted(blueprints.items()):
        lines.append(f'    "{tid}": [')
        for rule in rules:
            conds_repr = repr(rule.get("conditions", []))
            ls_repr    = repr(tuple(rule.get("logsource", ("windows", "process_creation"))))
            name_repr  = repr(rule.get("name", ""))
            lines.append(
                f'        {{"name": {name_repr}, "logsource": {ls_repr}, '
                f'"conditions": {conds_repr}}},'
            )
        lines.append('    ],')

    lines.append('}')

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nWrote {len(blueprints)} technique entries to {output_path}")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate TECHNIQUE_BLUEPRINTS from multiple authoritative sources."
    )
    parser.add_argument(
        "--stix", required=True,
        help="Path to MITRE ATT&CK enterprise STIX JSON bundle"
    )
    parser.add_argument(
        "--sigma", default="",
        help="Path to local Sigma rules directory (optional)"
    )
    parser.add_argument(
        "--output", default="blueprints_generated.py",
        help="Output Python file path (default: blueprints_generated.py)"
    )
    parser.add_argument(
        "--no-elastic", action="store_true",
        help="Skip fetching Elastic detection rules (no internet access)"
    )
    parser.add_argument(
        "--anthropic-key", default=os.environ.get("ANTHROPIC_API_KEY", ""),
        help="Anthropic API key for LLM-based ATT&CK detection text conversion"
    )
    parser.add_argument(
        "--max-rules", type=int, default=4,
        help="Maximum blueprint rules per technique (default: 4)"
    )
    args = parser.parse_args()

    # Load sources
    attack_techniques = load_attack_techniques(args.stix)

    sigma_rules = {}
    if args.sigma:
        sigma_rules = load_sigma_rules(args.sigma)

    elastic_rules = {}
    if not args.no_elastic:
        elastic_rules = fetch_elastic_rules()

    # Assemble
    blueprints = assemble_blueprints(
        attack_techniques,
        sigma_rules,
        elastic_rules,
        anthropic_api_key=args.anthropic_key or None,
        max_rules_per_technique=args.max_rules,
    )

    # Write output
    write_blueprints_file(blueprints, args.output)
    print("\nDone. Import with: from blueprints_generated import TECHNIQUE_BLUEPRINTS")


if __name__ == "__main__":
    main()