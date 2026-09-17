#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WireGuard .conf -> Xray WireGuard outbound converter GUI
Compatible with Xray WireGuard outbound schema used by Xray-core 26.x / 26.6.1.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


VALID_DOMAIN_STRATEGIES = [
    "ForceIP",
    "ForceIPv4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv6v4",
]


@dataclass
class ParseResult:
    interface: Dict[str, str] = field(default_factory=dict)
    peers: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ConversionError(Exception):
    pass


def normalize_key(key: str) -> str:
    """WireGuard keys are case-insensitive for our purposes."""
    return re.sub(r"\s+", "", key.strip().lower())


def strip_inline_comment(value: str) -> str:
    """Remove comments like 'value # note' or 'value ; note' without touching plain values."""
    value = value.strip()
    # Comments in WireGuard configs normally start after whitespace.
    value = re.split(r"\s+[;#]", value, maxsplit=1)[0].strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        value = value[1:-1].strip()
    return value


def split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_reserved(value: str) -> List[int]:
    """Parse Reserved = 1,2,3 / [1, 2, 3] / 1 2 3 into exactly three bytes when possible."""
    value = value.strip().strip("[]")
    if not value:
        return []
    parts = re.split(r"[,\s]+", value)
    nums: List[int] = []
    for part in parts:
        if not part:
            continue
        try:
            num = int(part, 0)
        except ValueError as exc:
            raise ConversionError(f"Invalid Reserved: {value}") from exc
        if not 0 <= num <= 255:
            raise ConversionError(f"Reserved values must be between 0 and 255: {value}")
        nums.append(num)
    if len(nums) != 3:
        raise ConversionError(f"Reserved must contain exactly 3 numbers, found {len(nums)}. Value: {value}")
    return nums


def parse_keepalive(value: str) -> int:
    try:
        keepalive = int(value.strip())
    except ValueError as exc:
        raise ConversionError(f"Invalid PersistentKeepalive: {value}") from exc
    if keepalive < 0:
        raise ConversionError("PersistentKeepalive cannot be negative")
    return keepalive


def parse_mtu(value: str) -> int:
    try:
        mtu = int(value.strip())
    except ValueError as exc:
        raise ConversionError(f"Invalid MTU: {value}") from exc
    if not 576 <= mtu <= 9000:
        raise ConversionError("MTU should normally be between 576 and 9000")
    return mtu


def parse_wireguard_config(text: str) -> ParseResult:
    result = ParseResult()
    current_section: Optional[str] = None
    current_peer: Optional[Dict[str, str]] = None

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        section_match = re.match(r"^\[(.+?)\]$", line)
        if section_match:
            section = section_match.group(1).strip().lower()
            current_section = section
            if section == "interface":
                current_peer = None
            elif section == "peer":
                current_peer = {}
                result.peers.append(current_peer)
            else:
                current_peer = None
                result.warnings.append(f"Section [{section}] on line {line_no} was ignored.")
            continue

        if "=" not in line:
            result.warnings.append(f"Line {line_no} could not be read and was ignored: {raw_line}")
            continue

        key, value = line.split("=", 1)
        key_norm = normalize_key(key)
        value_clean = strip_inline_comment(value)

        if current_section == "interface":
            result.interface[key_norm] = value_clean
        elif current_section == "peer" and current_peer is not None:
            current_peer[key_norm] = value_clean
        else:
            result.warnings.append(f"Key outside valid section on line {line_no} was ignored: {key.strip()}")

    return result


def build_xray_config(
    parsed: ParseResult,
    *,
    tag: str = "wireguard",
    domain_strategy: str = "ForceIP",
    mtu_override: Optional[str] = None,
    no_kernel_tun: bool = False,
    wrap_in_outbounds: bool = True,
) -> Tuple[dict, List[str]]:
    warnings = list(parsed.warnings)
    interface = parsed.interface
    peers = parsed.peers

    private_key = interface.get("privatekey", "").strip()
    if not private_key:
        raise ConversionError("PrivateKey not found in [Interface] section.")

    if not peers:
        raise ConversionError("No [Peer] section found in WireGuard file.")

    settings: dict = {
        "secretKey": private_key,
        "peers": [],
        "noKernelTun": bool(no_kernel_tun),
        "domainStrategy": domain_strategy if domain_strategy in VALID_DOMAIN_STRATEGIES else "ForceIP",
    }

    addresses = split_csv(interface.get("address", ""))
    if addresses:
        settings["address"] = addresses
    else:
        warnings.append("Address not found in [Interface]; Xray will use its default value.")

    mtu_source = mtu_override.strip() if mtu_override else interface.get("mtu", "").strip()
    if mtu_source:
        settings["mtu"] = parse_mtu(mtu_source)
    elif interface.get("mtu"):
        settings["mtu"] = parse_mtu(interface["mtu"])

    reserved_text = interface.get("reserved", "")
    if not reserved_text:
        for peer in peers:
            if peer.get("reserved"):
                reserved_text = peer["reserved"]
                warnings.append("Reserved was read from [Peer] and moved to outbound-level settings.")
                break
    if reserved_text:
        settings["reserved"] = parse_reserved(reserved_text)

    if interface.get("dns"):
        warnings.append("DNS is not directly transferred to WireGuard outbound; configure a separate dns/routing section in Xray.")

    xray_peers = []
    for index, peer in enumerate(peers, start=1):
        public_key = peer.get("publickey", "").strip()
        endpoint = peer.get("endpoint", "").strip()

        if not public_key:
            raise ConversionError(f"PublicKey not found in Peer number {index}.")
        if not endpoint:
            raise ConversionError(f"Endpoint not found in Peer number {index}.")

        xray_peer: dict = {
            "publicKey": public_key,
            "endpoint": endpoint,
        }

        allowed_ips = split_csv(peer.get("allowedips", ""))
        if allowed_ips:
            xray_peer["allowedIPs"] = allowed_ips

        psk = peer.get("presharedkey", "").strip()
        if psk:
            xray_peer["preSharedKey"] = psk

        keepalive_text = peer.get("persistentkeepalive", "").strip()
        if keepalive_text:
            xray_peer["keepAlive"] = parse_keepalive(keepalive_text)

        xray_peers.append(xray_peer)

    settings["peers"] = xray_peers

    outbound = {
        "tag": tag.strip() or "wireguard",
        "protocol": "wireguard",
        "settings": settings,
    }

    if wrap_in_outbounds:
        return {"outbounds": [outbound]}, warnings
    return outbound, warnings


if __name__ == "__main__":
    import json
    input_text = sys.stdin.read()
    if not input_text:
        sys.exit(0)
    parsed = parse_wireguard_config(input_text)
    file_mtu = parsed.interface.get("mtu", "").strip()
    cli_mtu = sys.argv[3] if len(sys.argv) > 3 else "1420"
    mtu_value = file_mtu or cli_mtu

    config, warnings = build_xray_config(
        parsed,
        tag=sys.argv[1] if len(sys.argv) > 1 else "wireguard",
        domain_strategy=sys.argv[2] if len(sys.argv) > 2 else "ForceIP",
        mtu_override=mtu_value,
        no_kernel_tun=(sys.argv[4].lower() == "true") if len(sys.argv) > 4 else True,
        wrap_in_outbounds=(sys.argv[5].lower() == "true") if len(sys.argv) > 5 else False,
    )
    print(json.dumps({"config": config, "warnings": warnings}))

