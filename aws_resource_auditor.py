#!/usr/bin/env python3
"""
aws_resource_auditor.py
========================

Enumerate resources across every AWS region for one or more profiles found in
an AWS credentials file, and highlight the delta between where a customer
*says* they have resources (--expected-regions) and where resources (or
merely enabled-but-unused regions) actually exist.

This is built for cloud engagement scoping / cleanup work: a customer says
"we only run things in us-east-1 and us-west-2." This script tells you:

  * Which other regions actually have resources in them (undocumented
    footprint -- a real finding).
  * Which regions are enabled but sitting empty (disablement candidates --
    reduces attack surface even if nothing is currently there).
  * Which regions are disabled entirely (good -- no action needed).
  * A full inventory of every resource found, per region, so remediation
    (delete it, migrate it, or update the asset list) is easy to action.

WHAT IT SCANS
-------------
For every *enabled* region, the script collects:
  - EC2 instances
  - EBS volumes
  - VPCs
  - RDS instances (incl. multi-AZ members) and RDS/Aurora clusters
  - Lambda functions
  - Classic Elastic Load Balancers (ELB)
  - Application/Network/Gateway Load Balancers (ELBv2)
  - S3 buckets (global service, bucketed into their actual region)
  - Everything else the account has tagged or that supports the Resource
    Groups Tagging API (`resourcegroupstaggingapi:GetResources`), which
    covers most other services (DynamoDB, SNS, SQS, CloudFormation, KMS,
    ECS/EKS, API Gateway, etc.) as a broad catch-all.

Results are de-duplicated by ARN, so a resource found by both an explicit
collector and the tagging-API catch-all is only counted once.

Disabled (opt-in-not-enabled) regions are NOT scanned -- calling a service
API in a disabled region simply fails, and a disabled region can't hold
running resources. A disabled region is treated as a *good* outcome.

HANDLING RESTRICTIVE READ-ONLY ROLES
-------------------------------------
Engagement credentials are often a minimal read-only role (e.g. AWS SSO's
AWSReadOnlyAccess) further locked down by a Service Control Policy, so one
or more collectors may get AccessDenied/UnauthorizedOperation in some or
all regions. The script never lets a denied collector fail the whole scan:
  - If SOME collectors in a region succeed, the resource count is reported
    as a MINIMUM (">=N") and the region's Finding is tagged "[INCOMPLETE:
    x/y collectors denied]" -- it will not be silently under-reported.
  - If EVERY collector in a region is denied, the count is shown as unknown
    ("-"), not zero, and the Finding reads "ERROR - could not enumerate".
  - By default the raw exceptions (which repeat the caller ARN and SCP ARN
    on every line) are NOT printed to STDOUT -- only quantified counts
    appear in the region summary table/panel and in
    5_collector_errors_<timestamp>.csv. Pass --verbose to print every raw
    error as it happens.

REQUIRED IAM PERMISSIONS (read-only)
-------------------------------------
    sts:GetCallerIdentity
    ec2:DescribeRegions
    ec2:DescribeInstances
    ec2:DescribeVolumes
    ec2:DescribeVpcs
    rds:DescribeDBInstances
    rds:DescribeDBClusters
    lambda:ListFunctions
    elasticloadbalancing:DescribeLoadBalancers
    s3:ListAllMyBuckets
    s3:GetBucketLocation
    tag:GetResources

INSTALL
-------
    pip install boto3 alive-progress rich

CONCURRENCY
-----------
Region scans are parallelized across a single shared thread pool covering
EVERY profile being audited at once (default: 8 concurrent region-scans,
tune with --max-workers). This bounds total concurrent AWS API calls at a
flat number regardless of how many accounts/regions are in play, rather
than multiplying a per-account pool by a per-region pool. Every AWS client
is additionally configured with adaptive retries (auto backoff on
Throttling/RequestLimitExceeded), so occasional throttling under
concurrency is absorbed by the SDK rather than showing up as a permissions
error. Account/region discovery (STS + DescribeRegions + S3 listing) stays
sequential per profile -- it's a handful of calls, not the bottleneck.
Pass --max-workers 1 for the old fully-sequential behavior.

USAGE
-----
    # Single profile, no expectations set (just inventories everything)
    python3 aws_resource_auditor.py --profile customer-prod

    # Single profile, flag anything outside these regions as unexpected
    python3 aws_resource_auditor.py --profile customer-prod \\
        --expected-regions us-east-1,us-west-2

    # Every profile in ~/.aws/credentials -- scanned concurrently
    python3 aws_resource_auditor.py --all-profiles \\
        --expected-regions us-east-1 us-west-2 eu-west-1

    # Turn concurrency up (faster, more AWS API pressure) or down/off
    python3 aws_resource_auditor.py --all-profiles --max-workers 16
    python3 aws_resource_auditor.py --all-profiles --max-workers 1

    # Custom credentials file / output location
    python3 aws_resource_auditor.py --all-profiles \\
        --credentials-file /path/to/credentials \\
        --output-dir ./audit_results

OUTPUT
------
Printed to STDOUT (per account):
  - Region summary table (resource count per region, unexpected regions
    highlighted, collector-error counts called out)
  - Findings panel (the "Number of ..." rollup metrics)
  - Collector-error details ONLY with --verbose (otherwise a single
    quantified line, e.g. "2 region(s), 9 collector error(s) total --
    suppressed")

Written to --output-dir (one row per account+region / account+region+type /
resource / collector-error, across ALL scanned accounts):
  1_region_summary_<timestamp>.csv
  2_resource_type_breakdown_<timestamp>.csv
  3_resource_inventory_<timestamp>.csv
  4_account_findings_summary_<timestamp>.csv
  5_collector_errors_<timestamp>.csv
"""

import argparse
import configparser
import csv
import os
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
        OperationNotPageableError,
        ProfileNotFound,
    )
except ImportError:
    print("ERROR: boto3 is required. Install with: pip install boto3", file=sys.stderr)
    sys.exit(1)

# Every AWS client uses adaptive retries -- if concurrent scanning ever does
# trigger throttling (Throttling/RequestLimitExceeded/TooManyRequests), the
# SDK backs off and retries automatically instead of surfacing it as a hard
# failure. This is the main safety net against "getting blocked by AWS";
# --max-workers just controls how much concurrency we offer it in the first
# place.
RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})

try:
    from alive_progress import alive_bar
except ImportError:
    print("ERROR: alive-progress is required. Install with: pip install alive-progress", file=sys.stderr)
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    print("ERROR: rich is required. Install with: pip install rich", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class ResourceRecord:
    resource_type: str
    resource_id: str
    name: str
    arn: str


@dataclass
class CollectorError:
    """A single failed API call, with just enough detail to quantify and
    troubleshoot restrictive read-only policies (e.g. AWSReadOnlyAccess +
    an SCP explicit deny) without dumping the full raw exception to STDOUT
    by default."""
    region: str
    collector: str
    code: str          # short AWS error code, e.g. AccessDenied, UnauthorizedOperation
    scp_denied: bool    # True if the error text indicates an SCP explicit deny
    message: str        # full exception text, shown only with --verbose


@dataclass
class RegionResult:
    region: str
    enabled: bool
    resource_count: Optional[int] = None  # None = unknown/error, not "zero"
    resources: List[ResourceRecord] = field(default_factory=list)
    errors: List[CollectorError] = field(default_factory=list)
    collector_total: int = 0  # how many collectors were attempted in this region
    expected: Optional[bool] = None  # None = user gave no --expected-regions
    finding: str = ""
    severity: str = "none"  # none|good|ok|info|warn|partial|finding|error


# --------------------------------------------------------------------------
# Explicit ("core") resource collectors
# --------------------------------------------------------------------------
# Each collector returns a list of ResourceRecord. Every collector is called
# independently and wrapped in try/except by the caller, so one missing
# permission or unsupported service in a given region doesn't blank out the
# whole region's results.

def _paginate(client, op_name: str, result_key: str, **kwargs) -> list:
    """Paginate an AWS API call, falling back to manual NextToken handling
    for operations without a registered paginator."""
    try:
        paginator = client.get_paginator(op_name)
        items = []
        for page in paginator.paginate(**kwargs):
            items.extend(page.get(result_key, []))
        return items
    except OperationNotPageableError:
        method = getattr(client, op_name)
        items = []
        resp = method(**kwargs)
        items.extend(resp.get(result_key, []))
        token = resp.get("NextToken")
        while token:
            resp = method(NextToken=token, **kwargs)
            items.extend(resp.get(result_key, []))
            token = resp.get("NextToken")
        return items


def _classify_error(region: str, collector: str, exc: Exception) -> CollectorError:
    """Turn a raw exception into a short, quantifiable CollectorError --
    used to silence noisy STDOUT dumps by default while still surfacing
    *how many* and *what kind* of permission gaps exist."""
    code = "Error"
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "ClientError")
    msg = str(exc)
    scp_denied = "service control policy" in msg.lower()
    return CollectorError(region=region, collector=collector, code=code,
                           scp_denied=scp_denied, message=msg)


def _tag_name(tags) -> str:
    if not tags:
        return ""
    for t in tags:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


def collect_ec2_instances(session, region, account_id, partition) -> List[ResourceRecord]:
    ec2 = session.client("ec2", region_name=region, config=RETRY_CONFIG)
    reservations = _paginate(ec2, "describe_instances", "Reservations")
    out = []
    for r in reservations:
        for inst in r.get("Instances", []):
            iid = inst["InstanceId"]
            out.append(ResourceRecord(
                resource_type="ec2:instance",
                resource_id=iid,
                name=_tag_name(inst.get("Tags")) or inst.get("State", {}).get("Name", ""),
                arn=f"arn:{partition}:ec2:{region}:{account_id}:instance/{iid}",
            ))
    return out


def collect_ebs_volumes(session, region, account_id, partition) -> List[ResourceRecord]:
    ec2 = session.client("ec2", region_name=region, config=RETRY_CONFIG)
    volumes = _paginate(ec2, "describe_volumes", "Volumes")
    out = []
    for v in volumes:
        vid = v["VolumeId"]
        out.append(ResourceRecord(
            resource_type="ec2:volume",
            resource_id=vid,
            name=_tag_name(v.get("Tags")),
            arn=f"arn:{partition}:ec2:{region}:{account_id}:volume/{vid}",
        ))
    return out


def collect_vpcs(session, region, account_id, partition) -> List[ResourceRecord]:
    ec2 = session.client("ec2", region_name=region, config=RETRY_CONFIG)
    vpcs = _paginate(ec2, "describe_vpcs", "Vpcs")
    out = []
    for v in vpcs:
        vid = v["VpcId"]
        label = _tag_name(v.get("Tags"))
        if v.get("IsDefault"):
            label = (label + " [default VPC]").strip()
        out.append(ResourceRecord(
            resource_type="ec2:vpc",
            resource_id=vid,
            name=label,
            arn=f"arn:{partition}:ec2:{region}:{account_id}:vpc/{vid}",
        ))
    return out


def collect_rds_instances(session, region, account_id, partition) -> List[ResourceRecord]:
    rds = session.client("rds", region_name=region, config=RETRY_CONFIG)
    dbs = _paginate(rds, "describe_db_instances", "DBInstances")
    out = []
    for db in dbs:
        arn = db.get("DBInstanceArn") or f"arn:{partition}:rds:{region}:{account_id}:db:{db['DBInstanceIdentifier']}"
        out.append(ResourceRecord(
            resource_type="rds:db",
            resource_id=db["DBInstanceIdentifier"],
            name=db.get("Engine", ""),
            arn=arn,
        ))
    return out


def collect_rds_clusters(session, region, account_id, partition) -> List[ResourceRecord]:
    rds = session.client("rds", region_name=region, config=RETRY_CONFIG)
    clusters = _paginate(rds, "describe_db_clusters", "DBClusters")
    out = []
    for c in clusters:
        arn = c.get("DBClusterArn") or f"arn:{partition}:rds:{region}:{account_id}:cluster:{c['DBClusterIdentifier']}"
        out.append(ResourceRecord(
            resource_type="rds:cluster",
            resource_id=c["DBClusterIdentifier"],
            name=c.get("Engine", ""),
            arn=arn,
        ))
    return out


def collect_lambda_functions(session, region, account_id, partition) -> List[ResourceRecord]:
    lam = session.client("lambda", region_name=region, config=RETRY_CONFIG)
    fns = _paginate(lam, "list_functions", "Functions")
    out = []
    for fn in fns:
        arn = fn.get("FunctionArn") or f"arn:{partition}:lambda:{region}:{account_id}:function:{fn['FunctionName']}"
        out.append(ResourceRecord(
            resource_type="lambda:function",
            resource_id=fn["FunctionName"],
            name=fn.get("Runtime", ""),
            arn=arn,
        ))
    return out


def collect_elb_classic(session, region, account_id, partition) -> List[ResourceRecord]:
    elb = session.client("elb", region_name=region, config=RETRY_CONFIG)
    lbs = _paginate(elb, "describe_load_balancers", "LoadBalancerDescriptions")
    out = []
    for lb in lbs:
        name = lb["LoadBalancerName"]
        out.append(ResourceRecord(
            resource_type="elb:classic-load-balancer",
            resource_id=name,
            name=name,
            arn=f"arn:{partition}:elasticloadbalancing:{region}:{account_id}:loadbalancer/{name}",
        ))
    return out


def collect_elbv2(session, region, account_id, partition) -> List[ResourceRecord]:
    elbv2 = session.client("elbv2", region_name=region, config=RETRY_CONFIG)
    lbs = _paginate(elbv2, "describe_load_balancers", "LoadBalancers")
    out = []
    for lb in lbs:
        arn = lb["LoadBalancerArn"]
        out.append(ResourceRecord(
            resource_type=f"elbv2:{lb.get('Type', 'load-balancer')}",
            resource_id=lb.get("LoadBalancerName", arn),
            name=lb.get("DNSName", ""),
            arn=arn,
        ))
    return out


CORE_COLLECTORS = [
    ("EC2 Instances", collect_ec2_instances),
    ("EBS Volumes", collect_ebs_volumes),
    ("VPCs", collect_vpcs),
    ("RDS Instances", collect_rds_instances),
    ("RDS Clusters", collect_rds_clusters),
    ("Lambda Functions", collect_lambda_functions),
    ("Classic Load Balancers", collect_elb_classic),
    ("ALB/NLB/GWLB", collect_elbv2),
]


def collect_s3_buckets_by_region(session, account_id, partition) -> Tuple[Dict[str, List[ResourceRecord]], List[CollectorError]]:
    """S3 is a global service -- list every bucket once, then resolve each
    bucket's actual region so it can be folded into that region's results."""
    errors: List[CollectorError] = []
    by_region: Dict[str, List[ResourceRecord]] = defaultdict(list)
    try:
        s3 = session.client("s3", region_name="us-east-1", config=RETRY_CONFIG)
        resp = s3.list_buckets()
    except (ClientError, BotoCoreError, EndpointConnectionError) as e:
        errors.append(_classify_error("global", "S3 ListBuckets", e))
        return by_region, errors

    for b in resp.get("Buckets", []):
        name = b["Name"]
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            region = loc or "us-east-1"
            if region == "EU":
                region = "eu-west-1"
        except (ClientError, BotoCoreError, EndpointConnectionError) as e:
            errors.append(_classify_error("global", f"S3 GetBucketLocation ({name})", e))
            region = "unknown"
        by_region[region].append(ResourceRecord(
            resource_type="s3:bucket",
            resource_id=name,
            name="",
            arn=f"arn:{partition}:s3:::{name}",
        ))
    return by_region, errors


def collect_tagged_resources(session, region, account_id, partition) -> List[ResourceRecord]:
    """Catch-all via the Resource Groups Tagging API -- covers most
    services not explicitly collected above (DynamoDB, SNS, SQS,
    CloudFormation, KMS, ECS/EKS, API Gateway, etc.)."""
    client = session.client("resourcegroupstaggingapi", region_name=region, config=RETRY_CONFIG)
    items = _paginate(client, "get_resources", "ResourceTagMappingList", ResourcesPerPage=100)
    out = []
    for item in items:
        arn = item["ResourceARN"]
        rtype, rid = _type_and_id_from_arn(arn)
        out.append(ResourceRecord(
            resource_type=rtype,
            resource_id=rid,
            name=_tag_name(item.get("Tags")),
            arn=arn,
        ))
    return out


def _type_and_id_from_arn(arn: str) -> Tuple[str, str]:
    """Best-effort parse of an ARN's resource type and resource id, handling
    both 'service:region:account:type/id' and 'service:region:account:type:id'
    ARN shapes."""
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return "unknown", arn
    service = parts[2]
    resource_part = parts[5]
    if "/" in resource_part:
        rtype, rid = resource_part.split("/", 1)
    elif ":" in resource_part:
        rtype, rid = resource_part.split(":", 1)
    else:
        rtype, rid = resource_part, resource_part
    return f"{service}:{rtype}", rid


# --------------------------------------------------------------------------
# Per-region scan orchestration
# --------------------------------------------------------------------------

def scan_region(session, account_id, partition, region, extra_records=None,
                 skip_tagging_api=False) -> Tuple[List[ResourceRecord], List[CollectorError], bool, int]:
    seen_arns: Set[str] = set()
    records: List[ResourceRecord] = []
    errors: List[CollectorError] = []
    any_success = False
    collector_total = len(CORE_COLLECTORS) + (0 if skip_tagging_api else 1)

    def add(rec: ResourceRecord):
        if rec.arn not in seen_arns:
            seen_arns.add(rec.arn)
            records.append(rec)

    for label, fn in CORE_COLLECTORS:
        try:
            for rec in fn(session, region, account_id, partition):
                add(rec)
            any_success = True
        except (ClientError, BotoCoreError, EndpointConnectionError) as e:
            errors.append(_classify_error(region, label, e))
        except Exception as e:  # defensive -- never let one collector kill the scan
            errors.append(_classify_error(region, label, e))

    if not skip_tagging_api:
        try:
            for rec in collect_tagged_resources(session, region, account_id, partition):
                add(rec)
            any_success = True
        except (ClientError, BotoCoreError, EndpointConnectionError) as e:
            errors.append(_classify_error(region, "Resource Groups Tagging API", e))
        except Exception as e:
            errors.append(_classify_error(region, "Resource Groups Tagging API", e))

    for rec in (extra_records or []):
        add(rec)
        any_success = True

    return records, errors, any_success, collector_total


def get_account_identity(session, bootstrap_region) -> Tuple[str, str]:
    sts = session.client("sts", region_name=bootstrap_region, config=RETRY_CONFIG)
    identity = sts.get_caller_identity()
    arn = identity["Arn"]
    partition = arn.split(":")[1]
    return identity["Account"], partition


def get_all_regions(session, bootstrap_region) -> List[Tuple[str, bool]]:
    """Returns [(region_name, enabled), ...]. A disabled (opt-in-not-enabled)
    region is a GOOD thing -- it can't hold running resources."""
    ec2 = session.client("ec2", region_name=bootstrap_region, config=RETRY_CONFIG)
    resp = ec2.describe_regions(AllRegions=True)
    out = []
    for r in resp["Regions"]:
        enabled = r["OptInStatus"] in ("opt-in-not-required", "opted-in")
        out.append((r["RegionName"], enabled))
    return sorted(out, key=lambda x: x[0])


# --------------------------------------------------------------------------
# Findings classification
# --------------------------------------------------------------------------

def classify(region_result: RegionResult, expected_regions: Optional[Set[str]]):
    r = region_result
    if not r.enabled:
        r.expected = None
        r.finding = "Disabled (good)"
        r.severity = "good"
        return

    # Whether this region is on the documented/expected list is knowable
    # regardless of whether we could enumerate what's inside it -- an
    # enabled region outside the expected footprint is itself a finding,
    # even when permissions block us from confirming what's running there.
    r.expected = (r.region in expected_regions) if expected_regions is not None else None

    if r.resource_count is None:
        # Every collector was denied -- resources are UNKNOWN, not zero.
        if expected_regions is None:
            r.finding = (f"ERROR - could not enumerate "
                         f"({len(r.errors)}/{r.collector_total} collectors denied -- check permissions)")
            r.severity = "error"
        elif r.expected:
            r.finding = (f"Expected region, but resource status UNKNOWN "
                         f"({len(r.errors)}/{r.collector_total} collectors denied -- check permissions)")
            r.severity = "error"
        else:
            r.finding = (f"FINDING - enabled region NOT expected; resource status UNCONFIRMED "
                         f"({len(r.errors)}/{r.collector_total} collectors denied) -- a region with "
                         f"no expected resources should not be enabled at all; MANUAL REVIEW REQUIRED")
            r.severity = "finding_unconfirmed"
        return

    if expected_regions is None:
        r.finding = "In use" if r.resource_count > 0 else "Enabled, no resources found"
        r.severity = "info" if r.resource_count > 0 else "none"
    else:
        if r.expected and r.resource_count > 0:
            r.finding = "OK - expected region, in use"
            r.severity = "ok"
        elif r.expected and r.resource_count == 0:
            r.finding = "Expected region, but NO resources found"
            r.severity = "info"
        elif not r.expected and r.resource_count > 0:
            r.finding = "FINDING - unexpected resources present"
            r.severity = "finding"
        else:  # not expected, zero resources (fully or partially confirmed)
            r.finding = "FINDING - enabled region not expected, unused (disablement candidate)"
            r.severity = "warn"

    # Some collectors succeeded (so resource_count is real) but others were
    # denied -- the count is a MINIMUM, not a confirmed total. Flag this
    # quantitatively rather than silently under-reporting.
    if r.errors:
        r.finding += (f" [INCOMPLETE: {len(r.errors)}/{r.collector_total} collectors denied "
                       f"-- count is a MINIMUM]")
        if r.severity in ("good", "ok", "info", "none"):
            r.severity = "partial"


# --------------------------------------------------------------------------
# Account-level rollup metrics
# --------------------------------------------------------------------------

def compute_account_metrics(region_results: List[RegionResult], expected_regions: Optional[Set[str]]) -> dict:
    m = Counter()
    m["total_regions_checked"] = len(region_results)
    for r in region_results:
        if not r.enabled:
            m["disabled_regions"] += 1
            continue
        m["enabled_regions"] += 1

        if r.resource_count is None:
            m["regions_with_errors"] += 1
            m["total_collector_errors"] += len(r.errors)
        else:
            if r.resource_count > 0:
                m["enabled_regions_with_resources"] += 1
            else:
                m["enabled_regions_without_resources"] += 1
            if r.errors:
                m["regions_with_partial_data"] += 1
                m["total_collector_errors"] += len(r.errors)

        if expected_regions is None:
            continue

        if r.expected:
            if r.resource_count is None:
                m["expected_regions_unknown"] += 1
            elif r.resource_count > 0:
                m["expected_regions_with_resources"] += 1
            else:
                m["expected_regions_without_resources"] += 1
        else:
            # An enabled region outside the expected footprint is a FINDING
            # on its own -- always counted here, even when we couldn't
            # enumerate what (if anything) is running in it.
            m["enabled_regions_not_expected"] += 1
            if r.resource_count is not None and r.resource_count > 0:
                m["unexpected_regions_with_resources"] += 1  # KEY FINDING -- confirmed
            elif r.resource_count == 0 and not r.errors:
                m["unused_enabled_regions_not_expected"] += 1  # KEY FINDING -- confirmed unused
            else:
                # resource_count is None, or 0-but-only-a-floor (some
                # collectors denied) -- we genuinely don't know if it's
                # empty. Still a finding: it shouldn't be enabled at all.
                m["unexpected_regions_unconfirmed"] += 1  # KEY FINDING -- inconclusive
    return m


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def split_regions(values: List[str]) -> Set[str]:
    out = set()
    for v in values:
        for piece in v.split(","):
            piece = piece.strip().lower()
            if piece:
                out.add(piece)
    return out


def parse_args():
    p = argparse.ArgumentParser(
        description="Enumerate AWS resources across every region for one or more profiles, "
                     "and flag regions used outside a documented/expected footprint.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    profile_group = p.add_mutually_exclusive_group(required=True)
    profile_group.add_argument("--profile", help="Scan only this profile from the credentials file.")
    profile_group.add_argument("--all-profiles", action="store_true",
                                help="Scan every profile found in the credentials file.")

    p.add_argument("--expected-regions", nargs="+", default=None, metavar="REGION",
                    help="Region(s) the customer expects to have resources in. "
                         "Comma- and/or space-separated, e.g. "
                         "--expected-regions us-east-1,us-west-2 or "
                         "--expected-regions us-east-1 us-west-2. "
                         "If omitted, the report is purely informational (nothing is "
                         "flagged as 'unexpected', but usage is still shown).")

    p.add_argument("--credentials-file", default="~/.aws/credentials",
                    help="Path to the AWS credentials file (default: ~/.aws/credentials).")
    p.add_argument("--regions", nargs="+", default=None, metavar="REGION",
                    help="Restrict the scan to these regions instead of every region in the "
                         "partition (comma- and/or space-separated). Mostly useful for testing.")
    p.add_argument("--bootstrap-region", default="us-east-1",
                    help="Region used to call STS/EC2 DescribeRegions to discover the account "
                         "and region list (default: us-east-1). Use a GovCloud/China region "
                         "here if auditing a profile in one of those partitions.")
    p.add_argument("--output-dir", default=None,
                    help="Directory to write CSV output to (default: "
                         "./aws_resource_audit_<timestamp>).")
    p.add_argument("--no-tagging-api", action="store_true",
                    help="Skip the Resource Groups Tagging API catch-all collector "
                         "(only the explicitly-coded resource types will be counted). "
                         "Use this if the account lacks tag:GetResources permission.")
    p.add_argument("--no-color", action="store_true", help="Disable colored/highlighted STDOUT output.")
    p.add_argument("--verbose", "-v", action="store_true",
                    help="Print the full raw error for every failed collector call (permission "
                         "denials, SCP explicit denies, etc.) as it happens. Without this flag, "
                         "those errors are silenced on STDOUT and instead surfaced as quantified "
                         "counts in the region summary table/CSV and in "
                         "5_collector_errors_<timestamp>.csv.")
    p.add_argument("--max-workers", type=int, default=8, metavar="N",
                    help="Max region-scans to run concurrently, pooled across every profile "
                         "being audited (default: 8). Each worker still calls the ~9 collectors "
                         "for its region one at a time, so this bounds total concurrent AWS API "
                         "calls, not multiplies against region/profile counts. Every client also "
                         "retries with adaptive backoff on throttling, so raising this is safe to "
                         "try if scans still feel slow; lower it if you actually get throttled. "
                         "Use --max-workers 1 to scan strictly sequentially (old behavior).")
    return p.parse_args()


def resolve_profiles(args) -> List[str]:
    cred_path = Path(os.path.expanduser(args.credentials_file))
    if not cred_path.exists():
        print(f"ERROR: credentials file not found: {cred_path}", file=sys.stderr)
        sys.exit(1)
    parser = configparser.ConfigParser()
    parser.read(cred_path)
    available = list(parser.sections())
    # configparser hides a literal [default] section behind DEFAULTSECT handling
    # in some edge cases; the AWS CLI also treats "default" as a valid profile name.
    if "default" not in available and parser.defaults():
        available.insert(0, "default")

    if not available:
        print(f"ERROR: no profiles found in {cred_path}", file=sys.stderr)
        sys.exit(1)

    if args.all_profiles:
        return available

    if args.profile not in available:
        print(f"ERROR: profile '{args.profile}' not found in {cred_path}.\n"
              f"Available profiles: {', '.join(available)}", file=sys.stderr)
        sys.exit(1)
    return [args.profile]


# --------------------------------------------------------------------------
# STDOUT rendering
# --------------------------------------------------------------------------

SEVERITY_STYLE = {
    "good": "dim green",
    "ok": "green",
    "info": "cyan",
    "none": "white",
    "partial": "bold yellow",
    "warn": "yellow",
    "finding": "bold red",
    "finding_unconfirmed": "red",  # enabled + unexpected, but couldn't confirm resources either way
    "error": "bold magenta",
}


def render_region_table(console: Console, profile: str, account_id: str,
                         region_results: List[RegionResult], expected_regions: Optional[Set[str]]):
    title = f"Region Summary -- profile '{profile}' (account {account_id})"
    table = Table(title=title, box=box.SIMPLE_HEAVY, show_lines=False, expand=False)
    table.add_column("Region", style="bold")
    table.add_column("Region Status", justify="center")
    table.add_column("Expected?", justify="center")
    table.add_column("Resource Count", justify="right")
    table.add_column("Collector Errors", justify="center")
    table.add_column("Finding")

    for r in region_results:
        style = SEVERITY_STYLE.get(r.severity, "white")
        region_status = "Enabled" if r.enabled else "Disabled"
        if expected_regions is None:
            expected_str = "n/a"
        elif r.expected is None:
            expected_str = "?"
        else:
            expected_str = "Yes" if r.expected else "No"
        if r.resource_count is None:
            count_str = "-"
        elif r.errors:
            count_str = f">={r.resource_count}"  # errors present -> count is a floor, not exact
        else:
            count_str = str(r.resource_count)
        if not r.enabled:
            errors_str = "n/a"
        elif r.errors:
            errors_str = f"{len(r.errors)}/{r.collector_total} denied"
        else:
            errors_str = "-"
        table.add_row(r.region, region_status, expected_str, count_str, errors_str,
                       r.finding, style=style)

    console.print(table)


def render_findings_panel(console: Console, profile: str, account_id: str, m: dict,
                           expected_regions: Optional[Set[str]]):
    lines = [
        f"Total Regions Checked:              {m.get('total_regions_checked', 0)}",
        f"Disabled Regions (good):            {m.get('disabled_regions', 0)}",
        f"Enabled Regions:                    {m.get('enabled_regions', 0)}",
        f"  - Enabled Regions With Resources: {m.get('enabled_regions_with_resources', 0)}",
        f"  - Enabled Regions, No Resources:  {m.get('enabled_regions_without_resources', 0)}",
        f"Regions That Errored (fully unknown): {m.get('regions_with_errors', 0)}",
    ]
    if m.get("regions_with_partial_data", 0) or m.get("total_collector_errors", 0):
        lines.append(
            f"Regions With INCOMPLETE Data (some collectors denied): "
            f"{m.get('regions_with_partial_data', 0)}  "
            f"(total collector errors: {m.get('total_collector_errors', 0)} -- "
            f"see collector_errors CSV / rerun with --verbose)"
        )
    if expected_regions is not None:
        lines += [
            "",
            f"Expected Regions With Resources:                    {m.get('expected_regions_with_resources', 0)}",
            f"Expected Regions With NO Resources:                 {m.get('expected_regions_without_resources', 0)}",
            f"Expected Regions - Resource Status Unknown:         {m.get('expected_regions_unknown', 0)}",
            "",
            f"Number of Enabled Regions Not Expected (FINDING):   {m.get('enabled_regions_not_expected', 0)}",
            f"  -> Confirmed: Unexpected Resources Present:              "
            f"{m.get('unexpected_regions_with_resources', 0)}",
            f"  -> Confirmed: Unused (safe disablement candidate):       "
            f"{m.get('unused_enabled_regions_not_expected', 0)}",
            f"  -> UNCONFIRMED (denied permissions -- manual review):    "
            f"{m.get('unexpected_regions_unconfirmed', 0)}",
        ]
        if m.get("unexpected_regions_unconfirmed", 0):
            lines.append(
                "\nNote: 'UNCONFIRMED' regions are enabled and NOT on the expected-regions "
                "list -- that alone is a finding -- but collector denials mean we could not "
                "verify whether they actually hold resources. Treat as an open item, not a "
                "clean bill of health."
            )
    else:
        lines.append("\n(no --expected-regions supplied -- nothing flagged as unexpected)")

    console.print(Panel("\n".join(lines), title=f"Findings -- {profile} ({account_id})",
                         border_style="cyan"))


# --------------------------------------------------------------------------
# CSV writers
# --------------------------------------------------------------------------

def write_csvs(output_dir: Path, region_rows, type_rows, inventory_rows, account_rows,
                error_rows, timestamp: str):
    output_dir.mkdir(parents=True, exist_ok=True)

    def _write(filename, header, rows):
        path = output_dir / filename
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
        return path

    p1 = _write(f"1_region_summary_{timestamp}.csv",
                ["Profile", "AccountId", "Region", "RegionStatus", "Expected",
                 "ResourceCount", "CountIsMinimum", "CollectorErrors", "CollectorsAttempted",
                 "Finding", "Severity"],
                region_rows)
    p2 = _write(f"2_resource_type_breakdown_{timestamp}.csv",
                ["Profile", "AccountId", "Region", "ResourceType", "Count",
                 "Expected", "Unexpected"],
                type_rows)
    p3 = _write(f"3_resource_inventory_{timestamp}.csv",
                ["Profile", "AccountId", "Region", "ResourceType", "ResourceId",
                 "ResourceName", "ARN", "Expected", "Unexpected"],
                inventory_rows)
    p4 = _write(f"4_account_findings_summary_{timestamp}.csv",
                ["Profile", "AccountId", "TotalRegionsChecked", "DisabledRegions",
                 "EnabledRegions", "EnabledRegionsWithResources",
                 "EnabledRegionsWithoutResources", "RegionsWithErrors",
                 "RegionsWithPartialData", "TotalCollectorErrors",
                 "ExpectedRegionsProvided", "ExpectedRegionsWithResources",
                 "ExpectedRegionsWithoutResources", "ExpectedRegionsResourceStatusUnknown",
                 "EnabledRegionsNotExpected_FINDING",
                 "UnexpectedRegionsWithResources_FINDING",
                 "UnusedEnabledRegionsNotExpected_FINDING",
                 "UnexpectedRegionsUnconfirmed_FINDING"],
                account_rows)
    p5 = _write(f"5_collector_errors_{timestamp}.csv",
                ["Profile", "AccountId", "Region", "Collector", "ErrorCode",
                 "SCPExplicitDeny", "Message"],
                error_rows)
    return [p1, p2, p3, p4, p5]


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def _scan_region_worker(profile: str, account_id: str, partition: str, region_name: str,
                         extra_records, skip_tagging_api: bool):
    """Runs in a worker thread. Creates its OWN boto3.Session rather than
    sharing one across threads -- Session objects (unlike Client objects)
    are not documented as thread-safe, and this keeps credential
    resolution/refresh fully isolated per thread regardless of how many
    regions or profiles are being scanned concurrently."""
    session = boto3.Session(profile_name=profile)
    records, errors, any_success, collector_total = scan_region(
        session, account_id, partition, region_name,
        extra_records=extra_records, skip_tagging_api=skip_tagging_api,
    )
    return profile, region_name, records, errors, any_success, collector_total


def main():
    args = parse_args()
    console = Console(no_color=args.no_color)

    expected_regions = split_regions(args.expected_regions) if args.expected_regions else None
    region_filter = split_regions(args.regions) if args.regions else None

    profiles = resolve_profiles(args)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir) if args.output_dir else Path(f"aws_resource_audit_{timestamp}")

    csv_region_rows = []
    csv_type_rows = []
    csv_inventory_rows = []
    csv_account_rows = []
    csv_error_rows = []

    # ---- Phase 1: sequential, cheap account/region discovery per profile ----
    # STS + DescribeRegions + S3 listing are each a handful of calls, so this
    # stays sequential and simple; the real cost -- collector calls fanned
    # out across every enabled region -- is what gets parallelized below.
    profile_ctxs = []
    for profile in profiles:
        console.print(f"[bold]Profile: {profile}[/bold] -- discovering account & regions...")
        try:
            session = boto3.Session(profile_name=profile)
        except ProfileNotFound as e:
            console.print(f"[bold red]ERROR:[/bold red] {e}")
            continue

        try:
            account_id, partition = get_account_identity(session, args.bootstrap_region)
        except (ClientError, BotoCoreError, NoCredentialsError, EndpointConnectionError) as e:
            console.print(f"[bold red]ERROR:[/bold red] could not authenticate profile "
                           f"'{profile}' (sts:GetCallerIdentity failed): {e}")
            continue

        try:
            regions = get_all_regions(session, args.bootstrap_region)
        except (ClientError, BotoCoreError, EndpointConnectionError) as e:
            console.print(f"[bold red]ERROR:[/bold red] could not list regions for "
                           f"'{profile}' / account {account_id}: {e}")
            continue

        if region_filter:
            regions = [(name, enabled) for name, enabled in regions if name in region_filter]
            if not regions:
                console.print(f"[yellow]No regions matched --regions filter for profile "
                               f"'{profile}'.[/yellow]")
                continue

        # S3 is global -- resolve buckets to their real region once, up front.
        s3_by_region, s3_errors = collect_s3_buckets_by_region(session, account_id, partition)

        region_results_map: Dict[str, RegionResult] = {}
        for region_name, enabled in regions:
            if not enabled:
                region_results_map[region_name] = RegionResult(region=region_name, enabled=False)

        profile_ctxs.append({
            "profile": profile, "account_id": account_id, "partition": partition,
            "regions": regions, "s3_by_region": s3_by_region, "s3_errors": s3_errors,
            "region_results_map": region_results_map,
        })

    # ---- Phase 2: build one flat job list across EVERY profile's enabled regions ----
    jobs = []
    for ctx in profile_ctxs:
        for region_name, enabled in ctx["regions"]:
            if enabled:
                jobs.append((ctx["profile"], ctx["account_id"], ctx["partition"], region_name,
                             ctx["s3_by_region"].get(region_name, []), args.no_tagging_api))

    # ---- Phase 3: scan every (profile, region) job through one shared pool ----
    # One shared executor + one shared progress bar across ALL profiles caps
    # total concurrent AWS calls at --max-workers regardless of how many
    # accounts are being audited, rather than multiplying a per-account pool
    # by a per-region pool. as_completed() is consumed here in the main
    # thread, so bar updates never need a lock.
    ctx_by_profile = {ctx["profile"]: ctx for ctx in profile_ctxs}
    if jobs:
        with alive_bar(len(jobs), title=f"scanning {len(jobs)} region(s) across "
                                         f"{len(profile_ctxs)} profile(s)", enrich_print=False) as bar:
            with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as pool:
                futures = [pool.submit(_scan_region_worker, *job) for job in jobs]
                for future in as_completed(futures):
                    profile, region_name, records, errors, any_success, collector_total = future.result()
                    rr = RegionResult(region=region_name, enabled=True, resources=records,
                                       errors=errors, collector_total=collector_total)
                    rr.resource_count = len(records) if any_success else None
                    ctx_by_profile[profile]["region_results_map"][region_name] = rr
                    bar.text = f"{profile}/{region_name} done"
                    bar()

    # ---- Phase 4: sequential rendering + CSV accumulation, one profile at a time ----
    for ctx in profile_ctxs:
        profile = ctx["profile"]
        account_id = ctx["account_id"]
        s3_errors = ctx["s3_errors"]
        region_results = [ctx["region_results_map"][name] for name, _ in ctx["regions"]]

        console.rule(f"[bold]Profile: {profile}[/bold]")

        for e in s3_errors:
            csv_error_rows.append([
                profile, account_id, e.region, e.collector, e.code,
                "Yes" if e.scp_denied else "No", e.message,
            ])

        # S3 bucket-location lookups happen once, globally, before the
        # per-region loop -- surface them the same quiet-by-default way.
        if s3_errors:
            if args.verbose:
                for e in s3_errors:
                    console.print(f"[yellow]S3 warning ({profile}) [{e.code}]: {e.message}[/yellow]")
            else:
                console.print(f"[yellow]{profile}: {len(s3_errors)} S3 bucket-location lookup "
                               f"error(s) (bucketed as 'unknown' region) -- rerun with --verbose "
                               f"or see 5_collector_errors CSV for detail.[/yellow]")

        for r in region_results:
            classify(r, expected_regions)

        render_region_table(console, profile, account_id, region_results, expected_regions)

        regions_with_errors = [r for r in region_results if r.errors]
        if regions_with_errors:
            if args.verbose:
                for r in regions_with_errors:
                    for e in r.errors:
                        scp_note = " (SCP explicit deny)" if e.scp_denied else ""
                        console.print(f"[dim]  {r.region} -- {e.collector} [{e.code}]{scp_note}: "
                                       f"{e.message}[/dim]")
            else:
                total_errs = sum(len(r.errors) for r in regions_with_errors)
                console.print(f"[dim]{len(regions_with_errors)} region(s), {total_errs} collector "
                               f"error(s) total -- suppressed (see Collector Errors column above, "
                               f"5_collector_errors CSV, or rerun with --verbose).[/dim]")

        metrics = compute_account_metrics(region_results, expected_regions)
        render_findings_panel(console, profile, account_id, metrics, expected_regions)
        console.print()

        # ---- accumulate CSV rows ----
        for r in region_results:
            expected_str = "n/a" if expected_regions is None else (
                "?" if r.expected is None else ("Yes" if r.expected else "No"))
            csv_region_rows.append([
                profile, account_id, r.region, "Enabled" if r.enabled else "Disabled",
                expected_str, r.resource_count if r.resource_count is not None else "",
                "Yes" if (r.errors and r.resource_count is not None) else "No",
                len(r.errors), r.collector_total if r.enabled else "",
                r.finding, r.severity,
            ])
            for e in r.errors:
                csv_error_rows.append([
                    profile, account_id, e.region, e.collector, e.code,
                    "Yes" if e.scp_denied else "No", e.message,
                ])

            type_counts = Counter(res.resource_type for res in r.resources)
            for rtype, count in sorted(type_counts.items()):
                unexpected = "Yes" if (expected_regions is not None and r.expected is False) else "No"
                csv_type_rows.append([
                    profile, account_id, r.region, rtype, count, expected_str, unexpected,
                ])

            for res in r.resources:
                unexpected = "Yes" if (expected_regions is not None and r.expected is False) else "No"
                csv_inventory_rows.append([
                    profile, account_id, r.region, res.resource_type, res.resource_id,
                    res.name, res.arn, expected_str, unexpected,
                ])

        csv_account_rows.append([
            profile, account_id,
            metrics.get("total_regions_checked", 0),
            metrics.get("disabled_regions", 0),
            metrics.get("enabled_regions", 0),
            metrics.get("enabled_regions_with_resources", 0),
            metrics.get("enabled_regions_without_resources", 0),
            metrics.get("regions_with_errors", 0),
            metrics.get("regions_with_partial_data", 0),
            metrics.get("total_collector_errors", 0),
            "Yes" if expected_regions is not None else "No",
            metrics.get("expected_regions_with_resources", 0) if expected_regions is not None else "",
            metrics.get("expected_regions_without_resources", 0) if expected_regions is not None else "",
            metrics.get("expected_regions_unknown", 0) if expected_regions is not None else "",
            metrics.get("enabled_regions_not_expected", 0) if expected_regions is not None else "",
            metrics.get("unexpected_regions_with_resources", 0) if expected_regions is not None else "",
            metrics.get("unused_enabled_regions_not_expected", 0) if expected_regions is not None else "",
            metrics.get("unexpected_regions_unconfirmed", 0) if expected_regions is not None else "",
        ])

    paths = write_csvs(output_dir, csv_region_rows, csv_type_rows, csv_inventory_rows,
                        csv_account_rows, csv_error_rows, timestamp)

    console.rule("[bold]Done[/bold]")
    console.print(f"CSV output written to: [bold]{output_dir}[/bold]")
    for p in paths:
        console.print(f"  - {p.name}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
