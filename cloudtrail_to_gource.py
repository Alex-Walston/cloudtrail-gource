#!/usr/bin/env python3
"""Convert CloudTrail events into Gource custom log format.

Supports two input modes:
  --log-dir PATH   Read raw CloudTrail JSON (.json / .json.gz) from disk
  --es-host URL    Query Elasticsearch (Filebeat-ingested events)

Identity-focused mode (default) organizes the tree by actor and threat category,
colors by threat level, and emits synthetic relationship edges so that identity
interactions (AssumeRole, AttachPolicy, etc.) are visually connected.
"""

import argparse
import glob
import gzip
import json
import os
import sys
from datetime import datetime

# ── Threat classification (MITRE ATT&CK–inspired) ───────────────────────────

THREAT_CATEGORIES = {
    # Persistence — establishing footholds
    "CreateUser": "persistence",
    "CreateRole": "persistence",
    "CreateAccessKey": "persistence",
    "CreateLoginProfile": "persistence",
    "UpdateLoginProfile": "persistence",
    "CreateGroup": "persistence",
    "CreateInstanceProfile": "persistence",
    "CreateServiceLinkedRole": "persistence",

    # Privilege escalation — gaining higher access
    "AttachUserPolicy": "privilege-escalation",
    "AttachRolePolicy": "privilege-escalation",
    "AttachGroupPolicy": "privilege-escalation",
    "PutUserPolicy": "privilege-escalation",
    "PutRolePolicy": "privilege-escalation",
    "PutGroupPolicy": "privilege-escalation",
    "AddUserToGroup": "privilege-escalation",
    "AssumeRole": "privilege-escalation",
    "UpdateAssumeRolePolicy": "privilege-escalation",
    "CreatePolicyVersion": "privilege-escalation",
    "SetDefaultPolicyVersion": "privilege-escalation",
    "PassRole": "privilege-escalation",

    # Defense evasion — hiding tracks
    "StopLogging": "defense-evasion",
    "DeleteTrail": "defense-evasion",
    "UpdateTrail": "defense-evasion",
    "PutEventSelectors": "defense-evasion",
    "DeleteFlowLogs": "defense-evasion",
    "DeleteDetector": "defense-evasion",
    "DisableOrganizationAdminAccount": "defense-evasion",

    # Credential access
    "GetSecretValue": "credential-access",
    "GetPasswordData": "credential-access",

    # Impact — destructive or disruptive
    "DeleteBucket": "impact",
    "DeleteBucketPolicy": "impact",
    "TerminateInstances": "impact",
    "DeleteDBInstance": "impact",
    "StopInstances": "impact",
    "DeleteAccessKey": "impact",
    "DeleteUser": "impact",
    "DeleteRole": "impact",
    "DetachUserPolicy": "impact",
    "DetachRolePolicy": "impact",
    "DetachGroupPolicy": "impact",
    "RemoveUserFromGroup": "impact",
    "DeletePolicy": "impact",
}

# Actions whose prefix suggests recon even if not explicitly listed
RECON_PREFIXES = ("List", "Describe", "Get", "Head", "Lookup", "Search", "Check")

THREAT_COLORS = {
    "privilege-escalation": "FF0000",   # red
    "defense-evasion":      "FF0000",   # red
    "persistence":          "FF6600",   # orange
    "credential-access":    "FF6600",   # orange
    "impact":               "E25444",   # red-orange
    "reconnaissance":       "FFD700",   # yellow
    "general":              "4488FF",   # blue (normal ops)
}

DENIED_COLOR = "FF00FF"  # magenta for access-denied events

SERVICE_COLORS = {
    "s3": "E25444", "kms": "8C4FFF", "iam": "DD344C", "ec2": "FF9900",
    "sts": "3B48CC", "lambda": "F68D2E", "dynamodb": "4053D6",
    "cloudtrail": "759C3E", "cloudformation": "E7157B", "sns": "D93848",
    "sqs": "FF4F8B", "glue": "6236FF", "config": "E25444", "logs": "759C3E",
    "monitoring": "FF4F8B", "organizations": "DD344C",
    "elasticloadbalancing": "8C4FFF", "autoscaling": "FF9900",
    "rds": "4053D6", "sso": "3B48CC", "access-analyzer": "DD344C",
}

# ── Relationship actions: actor → target identity ────────────────────────────

# Maps action names to the flattened request_parameters key holding the target
RELATIONSHIP_ACTIONS = {
    "AssumeRole":         "roleArn",
    "AttachUserPolicy":   "userName",
    "AttachRolePolicy":   "roleName",
    "AttachGroupPolicy":  "groupName",
    "DetachUserPolicy":   "userName",
    "DetachRolePolicy":   "roleName",
    "DetachGroupPolicy":  "groupName",
    "PutUserPolicy":      "userName",
    "PutRolePolicy":      "roleName",
    "PutGroupPolicy":     "groupName",
    "AddUserToGroup":     "userName",
    "RemoveUserFromGroup":"userName",
}

# ── Raw CloudTrail log reader ──────────────────────────────────────────────

def raw_record_to_src(record):
    """Convert a raw CloudTrail JSON record to the nested dict format
    that the existing helper functions expect (Filebeat/ES schema)."""
    ui = record.get("userIdentity", {})
    sc = ui.get("sessionContext", {})
    si = sc.get("sessionIssuer", {})
    rp = record.get("requestParameters") or {}

    return {
        "@timestamp": record.get("eventTime", ""),
        "aws": {
            "cloudtrail": {
                "user_identity": {
                    "type": ui.get("type", ""),
                    "arn": ui.get("arn", ""),
                    "invoked_by": ui.get("invokedBy", ""),
                    "session_context": {
                        "session_issuer": {
                            "arn": si.get("arn", ""),
                        }
                    },
                },
                "flattened": {
                    "request_parameters": rp,
                },
            }
        },
        "event": {
            "action": record.get("eventName", ""),
            "provider": record.get("eventSource", ""),
            "outcome": "failure" if record.get("errorCode") else "success",
        },
        "source": {
            "ip": record.get("sourceIPAddress", ""),
        },
    }


def load_cloudtrail_files(log_dir):
    """Read all .json and .json.gz CloudTrail files under log_dir.
    Returns a list of converted source dicts, sorted by timestamp."""
    sources = []
    patterns = [
        os.path.join(log_dir, "**", "*.json"),
        os.path.join(log_dir, "**", "*.json.gz"),
    ]
    paths = set()
    for pat in patterns:
        paths.update(glob.glob(pat, recursive=True))

    for path in paths:
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Skipping {path}: {e}", file=sys.stderr)
            continue

        records = data.get("Records", []) if isinstance(data, dict) else data
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if not rec.get("eventName"):
                continue
            sources.append(raw_record_to_src(rec))

    sources.sort(key=lambda s: s.get("@timestamp", ""))
    print(f"Loaded {len(sources)} events from {len(paths)} files", file=sys.stderr)
    return sources


# ── Fields to fetch from ES ─────────────────────────────────────────────────

FIELDS = [
    "@timestamp",
    "aws.cloudtrail.user_identity.arn",
    "aws.cloudtrail.user_identity.type",
    "aws.cloudtrail.user_identity.invoked_by",
    "aws.cloudtrail.user_identity.session_context.session_issuer.arn",
    "aws.cloudtrail.flattened.request_parameters",
    "event.action",
    "event.provider",
    "event.outcome",
    "source.ip",
    "source.address",
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def extract_username(src):
    ui = src.get("aws", {}).get("cloudtrail", {}).get("user_identity", {})
    identity_type = ui.get("type", "")
    arn = ui.get("arn", "")
    invoked_by = ui.get("invoked_by", "")

    if identity_type == "Root":
        return "root"
    if identity_type == "AWSService":
        return invoked_by.split(".")[0] if invoked_by else "aws-service"
    if identity_type == "AssumedRole" and arn:
        parts = arn.split("/")
        return parts[1] if len(parts) >= 2 else arn.rsplit(":", 1)[-1]
    if arn:
        return arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]
    return "unknown"


def short_name_from_arn(arn):
    """Extract a short name from any ARN or plain name."""
    if not arn:
        return None
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    if ":" in arn:
        return arn.rsplit(":", 1)[-1]
    return arn


def get_session_issuer(src):
    """For AssumedRole events, return the role ARN that issued the session."""
    sc = (src.get("aws", {}).get("cloudtrail", {}).get("user_identity", {})
          .get("session_context", {}).get("session_issuer", {}))
    return sc.get("arn", "")


def classify_threat(action):
    if action in THREAT_CATEGORIES:
        return THREAT_CATEGORIES[action]
    if action.startswith(RECON_PREFIXES):
        return "reconnaissance"
    return "general"


def get_service_short(provider):
    return provider.split(".")[0] if provider else "unknown"


def map_action_type(action):
    ADD = ("Create", "Put", "Run", "Attach", "Add", "Register", "Allocate")
    DEL = ("Delete", "Remove", "Deregister", "Terminate", "Detach", "Release")
    if action.startswith(ADD):
        return "A"
    if action.startswith(DEL):
        return "D"
    return "M"


def get_request_param(src, key):
    """Get a value from flattened.request_parameters."""
    rp = (src.get("aws", {}).get("cloudtrail", {})
          .get("flattened", {}).get("request_parameters", {}))
    return rp.get(key, "")


def get_source_ip(src):
    """Extract source IP/address, falling back to invoked_by for AWS services."""
    ip = src.get("source", {}).get("ip", "")
    if ip:
        return ip
    addr = src.get("source", {}).get("address", "")
    if addr:
        return addr
    invoked_by = (src.get("aws", {}).get("cloudtrail", {})
                  .get("user_identity", {}).get("invoked_by", ""))
    if invoked_by:
        return invoked_by.split(".")[0]
    return "no-ip"


def get_display_name(src):
    """Build a Gource avatar label: 'username [IdentityType]'."""
    ui = src.get("aws", {}).get("cloudtrail", {}).get("user_identity", {})
    identity_type = ui.get("type", "")
    username = extract_username(src)
    return f"{username} [{identity_type}]" if identity_type else username


def get_arn(src):
    """Get the full ARN for the actor, falling back to invoked_by."""
    ui = src.get("aws", {}).get("cloudtrail", {}).get("user_identity", {})
    arn = ui.get("arn", "")
    if arn:
        return arn
    invoked_by = ui.get("invoked_by", "")
    if invoked_by:
        return invoked_by
    return "unknown"


# ── CLI & query ──────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Convert CloudTrail events to identity-focused Gource visualization")
    # Input source (pick one)
    inp = p.add_mutually_exclusive_group()
    inp.add_argument("--log-dir",
                     help="Path to directory of raw CloudTrail JSON files "
                          "(.json / .json.gz). Searched recursively.")
    inp.add_argument("--es-host", default=None,
                     help="Elasticsearch host (default: http://localhost:9200)")
    p.add_argument("--index", default="filebeat-*")
    p.add_argument("--exclude-users", nargs="*", default=["filebeat-cloudtrail"],
                   help="Usernames to exclude")
    p.add_argument("--start-date", help="ISO 8601")
    p.add_argument("--end-date", help="ISO 8601")
    p.add_argument("-o", "--output", help="Output file (default: stdout)")
    p.add_argument("--mode", choices=["threat", "service"], default="threat",
                   help="threat = identity-focused threat view (default), "
                        "service = original service-colored view")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args()


def build_query(args):
    must = [{"exists": {"field": "aws.cloudtrail.user_identity.type"}}]
    if args.start_date or args.end_date:
        ts_range = {}
        if args.start_date:
            ts_range["gte"] = args.start_date
        if args.end_date:
            ts_range["lte"] = args.end_date
        must.append({"range": {"@timestamp": ts_range}})

    must_not = []
    for user in (args.exclude_users or []):
        must_not.append({"wildcard": {"aws.cloudtrail.user_identity.arn": f"*{user}*"}})

    return {"bool": {"must": must, "must_not": must_not}}


# ── Main ─────────────────────────────────────────────────────────────────────

def iter_sources_from_es(args):
    """Yield source dicts by paginating through Elasticsearch."""
    from elasticsearch import Elasticsearch
    es = Elasticsearch(args.es_host)
    query = build_query(args)
    search_after = None
    while True:
        body = {
            "size": 1000,
            "query": query,
            "sort": [{"@timestamp": "asc"}],
            "_source": FIELDS,
        }
        if search_after:
            body["search_after"] = search_after
        resp = es.search(index=args.index, body=body)
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for hit in hits:
            yield hit["_source"]
        search_after = hits[-1]["sort"]


def iter_sources(args):
    """Return an iterable of source dicts from either local files or ES."""
    if args.log_dir:
        return load_cloudtrail_files(args.log_dir)
    es_host = args.es_host or "http://localhost:9200"
    args.es_host = es_host
    return iter_sources_from_es(args)


def main():
    args = parse_args()
    out = open(args.output, "w") if args.output else sys.stdout

    total = 0

    def emit(line):
        nonlocal total
        out.write(line + "\n")
        total += 1

    # Collect all events first so we can add heartbeats
    events = []       # (epoch, display_name, action_type, filepath, color)
    seen_users = {}   # display_name -> first_seen epoch
    exclude = set(args.exclude_users or [])

    try:
        for src in iter_sources(args):
            ts_str = src.get("@timestamp")
            action = src.get("event", {}).get("action", "")
            provider = src.get("event", {}).get("provider", "")
            outcome = src.get("event", {}).get("outcome", "success")

            if not ts_str or not action:
                continue

            username = extract_username(src)
            if username in exclude:
                continue

            display = get_display_name(src)
            arn = get_arn(src)
            source_ip = get_source_ip(src)
            epoch = int(datetime.fromisoformat(
                ts_str.replace("Z", "+00:00")).timestamp())
            action_type = map_action_type(action)
            service = get_service_short(provider)

            if display not in seen_users:
                seen_users[display] = epoch

            if args.mode == "service":
                filepath = f"/{username}/{service}/{source_ip}/{action}"
                color = SERVICE_COLORS.get(service, "AAAAAA")
            else:
                threat = classify_threat(action)
                denied = outcome == "failure"

                if denied:
                    filepath = f"/{username}/{arn}/DENIED/{source_ip}/{service}/{action}"
                    color = DENIED_COLOR
                else:
                    filepath = f"/{username}/{arn}/{threat}/{source_ip}/{service}/{action}"
                    color = THREAT_COLORS[threat]

                # ── Relationship edges ───────────────────────────
                if action in RELATIONSHIP_ACTIONS:
                    param_key = RELATIONSHIP_ACTIONS[action]
                    target_raw = get_request_param(src, param_key)
                    target = short_name_from_arn(target_raw)

                    if target and target != username:
                        rel_path = f"/{target}/targeted-by/{username}/{source_ip}/{action}"
                        events.append((epoch, display, action_type,
                                       rel_path, color))

                # ── Session-issuer link for AssumedRole ──────────
                ui_type = (src.get("aws", {}).get("cloudtrail", {})
                           .get("user_identity", {}).get("type", ""))
                if ui_type == "AssumedRole":
                    issuer_arn = get_session_issuer(src)
                    issuer = short_name_from_arn(issuer_arn)
                    if issuer and issuer != username:
                        filepath = f"/{issuer}/roles/{username}/{arn}/{threat}/{source_ip}/{action}"

            events.append((epoch, display, action_type, filepath, color))

        # ── Heartbeats: keep every user visible for the entire timeline ──
        if events:
            min_ts = events[0][0]
            max_ts = events[-1][0]
            heartbeat_interval = max(30, (max_ts - min_ts) // 200)
            hb_color = "333355"  # dim, nearly invisible

            for display, first_seen in seen_users.items():
                # Extract username from display name for the path
                uname = display.split(" [")[0]
                hb_path = f"/{uname}/.presence"
                t = first_seen
                while t <= max_ts:
                    events.append((t, display, "M", hb_path, hb_color))
                    t += heartbeat_interval

        # Sort everything by timestamp and write out
        events.sort(key=lambda e: e[0])
        for epoch, display, action_type, filepath, color in events:
            if args.no_color:
                emit(f"{epoch}|{display}|{action_type}|{filepath}")
            else:
                emit(f"{epoch}|{display}|{action_type}|{filepath}|{color}")

        print(f"Wrote {total} events", file=sys.stderr)
    finally:
        if args.output and out is not sys.stdout:
            out.close()


if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    main()
