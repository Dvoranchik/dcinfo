#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
dcinfo - find AD domain controllers (IP, DNS name, site) without admin rights.

The same file works in two ways.

1) As a NetExec module (nothing is executed on the target):

       cp dcinfo.py ~/.nxc/modules/
       nxc smb 10.0.0.50 -u user -p 'Password' -M dcinfo          # SMB, any domain host
       nxc smb 10.0.0.50 -u user -p 'Password' -M dcinfo -o ZONES=True
       nxc ldap dc01.corp.local -u user -p 'Password' -M dcinfo   # LDAP, target is a DC

2) Standalone, e.g. on a domain-joined workstation with a regular user:

       python dcinfo.py --local
       python dcinfo.py --domain corp.local --dc 10.0.0.5 --user user --password 'Password'

SMB path (no admin, no code on the target):

    \pipe\dssetup  -> DsRolerGetPrimaryDomainInformation  (role, DNS domain, forest)
    \pipe\netlogon -> DsrGetDcNameEx2 (MS-NRPC opnum 34)   (DC FQDN + IP + site + flags)

The netlogon call makes the *target* run the DC locator (DNS SRV + LDAP ping) and
return the answer, which is why no privileges and no execution on the target are
needed. DNS SRV against the discovered DC then lists every DC of the domain.

What it does NOT do: no nslookup/nltest/dsquery/powershell/cmd child processes,
no remote command execution, no files written to the target, no admin rights.

License: MIT
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import random
import socket
import struct
import sys

try:  # NetExec is optional: the same file is usable as a standalone CLI
    from nxc.helpers.misc import CATEGORY
except Exception:  # pragma: no cover - depends on the runtime

    class CATEGORY:  # type: ignore[no-redef]
        ENUMERATION = "Enumeration"


try:
    from impacket.ldap.ldapasn1 import Scope as _LdapScope
except Exception:  # pragma: no cover - impacket is present inside nxc
    _LdapScope = None


DNS_PORT = 53
DNS_TIMEOUT = 2.0
DNS_RETRIES = 2

DNS_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
}

ROOTDSE_ATTRIBUTES = (
    "dnsHostName",
    "serverName",
    "ldapServiceName",
    "defaultNamingContext",
    "rootDomainNamingContext",
    "configurationNamingContext",
    "namingContexts",
    "domainControllerFunctionality",
    "forestFunctionality",
    "domainFunctionality",
    "isGlobalCatalogReady",
    "isSynchronized",
    "supportedLDAPVersion",
    "dsServiceName",
)

FUNCTIONAL_LEVELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016 / 2019 / 2022 / 2025",
}

# Roles published in DNS by every DC (MS-ADTS 6.1.1 / RFC 2782).
SRV_TEMPLATES = (
    ("_ldap._tcp.dc._msdcs.{domain}", "ldap"),
    ("_kerberos._tcp.dc._msdcs.{domain}", "kerberos"),
    ("_ldap._tcp.pdc._msdcs.{domain}", "pdc"),
    ("_ldap._tcp.gc._msdcs.{domain}", "gc"),
    ("_gc._tcp.{domain}", "gc"),
    ("_kpasswd._tcp.{domain}", "kpasswd"),
    ("_ldap._tcp.{domain}", "ldap"),
)


# --------------------------------------------------------------------------- #
# DNS wire protocol (stdlib only: no dnspython, no subprocess)
# --------------------------------------------------------------------------- #
def _encode_name(name):
    """Encode a DNS name into wire format (length prefixed labels)."""
    payload = bytearray()
    for label in name.strip(".").split("."):
        if not label:
            continue
        try:
            raw = label.encode("idna")
        except UnicodeError:
            raw = label.encode("utf-8", "ignore")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        payload.append(len(raw))
        payload += raw
    payload.append(0)
    return bytes(payload)


def _decode_name(data, offset):
    """Decode a (possibly compressed) DNS name, return (name, next_offset)."""
    labels = []
    next_offset = offset
    jumped = False
    hops = 0

    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            return ".".join(labels), next_offset
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            jumped = True
            hops += 1
            if hops > 20:
                raise ValueError("DNS compression loop")
            offset = pointer
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label length")
        labels.append(data[offset + 1: offset + 1 + length].decode("latin-1"))
        offset += 1 + length
        if not jumped:
            next_offset = offset


def _build_query(name, qtype):
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1, one question
    question = _encode_name(name) + struct.pack(">HH", DNS_TYPES[qtype], 1)
    return txid, header + question


def _parse_response(data, txid):
    """Parse a DNS response. Returns (records, rcode, truncated)."""
    if len(data) < 12:
        raise ValueError("short DNS response")
    rid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", data[:12])
    if rid != txid:
        raise ValueError("DNS transaction id mismatch")

    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    if rcode not in (0, 3) or truncated:
        return [], rcode, truncated

    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4

    records = []
    for _ in range(ancount):
        _, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset: offset + 10])
        offset += 10
        rdata_offset = offset
        offset += rdlength
        if offset > len(data):
            break

        if rtype == 33 and rdlength >= 7:  # SRV
            priority, weight, port = struct.unpack(">HHH", data[rdata_offset: rdata_offset + 6])
            target, _ = _decode_name(data, rdata_offset + 6)
            records.append(
                {
                    "type": "SRV",
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                    "ttl": ttl,
                }
            )
        elif rtype == 1 and rdlength == 4:  # A
            records.append(
                {"type": "A", "address": socket.inet_ntoa(data[rdata_offset: rdata_offset + 4]), "ttl": ttl}
            )
        elif rtype == 28 and rdlength == 16:  # AAAA
            records.append(
                {
                    "type": "AAAA",
                    "address": socket.inet_ntop(socket.AF_INET6, data[rdata_offset: rdata_offset + 16]),
                    "ttl": ttl,
                }
            )
        elif rtype == 12:  # PTR
            target, _ = _decode_name(data, rdata_offset)
            records.append({"type": "PTR", "target": target, "ttl": ttl})
        elif rtype == 5:  # CNAME
            target, _ = _decode_name(data, rdata_offset)
            records.append({"type": "CNAME", "target": target, "ttl": ttl})

    return records, rcode, truncated


def _recv_exact(sock, size):
    buffer = b""
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ValueError("connection closed by DNS server")
        buffer += chunk
    return buffer


def _udp_exchange(server, packet, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, DNS_PORT))
        data, _ = sock.recvfrom(4096)
        return data


def _tcp_exchange(server, packet, timeout):
    """Fallback for truncated UDP answers (TC bit), RFC 1035 4.2.2."""
    with socket.create_connection((server, DNS_PORT), timeout=timeout) as sock:
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, length)


class DNSResolver:
    """Minimal stub resolver that can be pinned to a specific DNS server."""

    def __init__(self, servers=None, timeout=DNS_TIMEOUT, retries=DNS_RETRIES):
        self.servers = []
        for server in servers or []:
            server = str(server or "").strip()
            if server and server not in self.servers:
                self.servers.append(server)
        self.timeout = float(timeout)
        self.retries = max(1, int(retries))
        self.cache = {}
        self.errors = []
        self.dead = set()

    def query(self, name, qtype="A"):
        key = (name.rstrip(".").lower(), qtype)
        if key in self.cache:
            return self.cache[key]

        result = []
        for server in self.servers:
            if server in self.dead:
                continue
            answered = False
            for _ in range(self.retries):
                try:
                    result = self._ask(server, name, qtype)
                    answered = True
                except Exception as exc:  # network error, timeout, malformed packet
                    self.errors.append(f"{server} {name}/{qtype}: {exc}")
                    result = []
                    continue
                break
            if not answered:
                # do not spend the whole run on an unreachable resolver
                self.dead.add(server)
            if result:
                break

        self.cache[key] = result
        return result

    def _ask(self, server, name, qtype):
        txid, packet = _build_query(name, qtype)
        try:
            data = _udp_exchange(server, packet, self.timeout)
            records, rcode, truncated = _parse_response(data, txid)
            if truncated:
                data = _tcp_exchange(server, packet, self.timeout)
                records, rcode, truncated = _parse_response(data, txid)
        except OSError:
            # firewalls often drop UDP/53 while TCP/53 is allowed, or the other way round
            data = _tcp_exchange(server, packet, self.timeout)
            records, rcode, truncated = _parse_response(data, txid)
        if rcode == 3:  # NXDOMAIN: the name simply does not exist
            return []
        if rcode:
            raise ValueError(f"DNS rcode {rcode}")
        return records

    def srv(self, name):
        records = []
        for record in self.query(name, "SRV"):
            if record.get("type") == "SRV":
                record = dict(record)
                record["target"] = record["target"].rstrip(".").lower()
                records.append(record)
        records.sort(key=lambda item: (item["priority"], -item["weight"]))
        return records

    def addresses(self, host):
        host = (host or "").strip().rstrip(".")
        if not host:
            return []
        found = []
        for qtype in ("A", "AAAA"):
            for record in self.query(host, qtype):
                if record.get("type") in ("A", "AAAA") and record["address"] not in found:
                    found.append(record["address"])
        if not found:  # last resort: OS resolver (still no subprocess)
            try:
                for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
                    if family in (socket.AF_INET, socket.AF_INET6) and sockaddr[0] not in found:
                        found.append(sockaddr[0])
            except OSError:
                pass
        return found

    def ptr(self, address):
        try:
            reverse = ipaddress.ip_address(address).reverse_pointer
        except ValueError:
            return ""
        records = self.query(reverse, "PTR")
        for record in records:
            if record.get("type") == "PTR":
                return record["target"].rstrip(".")
        return ""


# --------------------------------------------------------------------------- #
# Local machine context: DNS servers / domain / native DC locator
# --------------------------------------------------------------------------- #
def windows_network_info():
    """Return {'domain': str, 'dns': [ip, ...]} from the Windows IP helper API."""
    if os.name != "nt":
        return {"domain": "", "dns": []}

    import ctypes
    from ctypes import wintypes

    class IP_ADDR_STRING(ctypes.Structure):
        pass

    IP_ADDR_STRING._fields_ = [
        ("Next", ctypes.POINTER(IP_ADDR_STRING)),
        ("IpAddress", ctypes.c_char * 16),
        ("IpMask", ctypes.c_char * 16),
        ("Context", wintypes.DWORD),
    ]

    class FIXED_INFO(ctypes.Structure):
        _fields_ = [
            ("HostName", ctypes.c_char * 132),
            ("DomainName", ctypes.c_char * 132),
            ("CurrentDnsServer", ctypes.POINTER(IP_ADDR_STRING)),
            ("DnsServerList", IP_ADDR_STRING),
            ("NodeType", wintypes.UINT),
            ("ScopeId", ctypes.c_char * 260),
            ("EnableRouting", wintypes.UINT),
            ("EnableProxy", wintypes.UINT),
            ("EnableDns", wintypes.UINT),
        ]

    try:
        iphlpapi = ctypes.windll.iphlpapi
        size = wintypes.ULONG(0)
        if iphlpapi.GetNetworkParams(None, ctypes.byref(size)) not in (0, 111) or not size.value:
            return {"domain": "", "dns": []}
        buffer = ctypes.create_string_buffer(size.value)
        if iphlpapi.GetNetworkParams(buffer, ctypes.byref(size)) != 0:
            return {"domain": "", "dns": []}
        fixed = ctypes.cast(buffer, ctypes.POINTER(FIXED_INFO)).contents
    except Exception:
        return {"domain": "", "dns": []}

    servers = []
    node = fixed.DnsServerList
    guard = 0
    while guard < 16:
        guard += 1
        address = node.IpAddress.decode("latin-1", "ignore").strip("\x00").strip()
        if address and address not in servers:
            servers.append(address)
        if not node.Next:
            break
        node = node.Next.contents

    domain = fixed.DomainName.decode("latin-1", "ignore").strip("\x00").strip()
    return {"domain": domain, "dns": servers}


def posix_dns_servers():
    servers = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("nameserver", "nameserver6"):
                    if parts[1] not in servers:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


def posix_domain():
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("search", "domain"):
                    for candidate in parts[1:]:
                        if "." in candidate:
                            return candidate.strip(".")
    except OSError:
        pass
    return ""


def system_context():
    """Domain name and DNS servers of the machine running this code."""
    if os.name == "nt":
        info = windows_network_info()
        return {"domain": info["domain"].strip("."), "dns": info["dns"]}
    return {"domain": posix_domain(), "dns": posix_dns_servers()}


if os.name == "nt":
    import ctypes

    class _GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class _DOMAIN_CONTROLLER_INFO(ctypes.Structure):
        _fields_ = [
            ("DomainControllerName", ctypes.c_wchar_p),
            ("DomainControllerAddress", ctypes.c_wchar_p),
            ("DomainControllerAddressType", ctypes.c_ulong),
            ("DomainGuid", _GUID),
            ("DomainName", ctypes.c_wchar_p),
            ("DnsForestName", ctypes.c_wchar_p),
            ("Flags", ctypes.c_ulong),
            ("DcSiteName", ctypes.c_wchar_p),
            ("ClientSiteName", ctypes.c_wchar_p),
        ]


DS_FLAGS = {
    0x00000001: "PDC",
    0x00000004: "GC",
    0x00000008: "LDAP",
    0x00000010: "DS",
    0x00000020: "KDC",
    0x00000040: "TIMESERV",
    0x00000080: "CLOSEST",
    0x00000100: "WRITABLE",
    0x00000200: "GOOD_TIMESERV",
    0x00002000: "WEBSERVER",
    0x20000000: "DNS_CONTROLLER",
    0x40000000: "DNS_DOMAIN",
    0x80000000: "DNS_FOREST",
}


def windows_dc_info(domain=None):
    """Locate the DC the OS itself would use (DsGetDcName) - one documented API call."""
    if os.name != "nt":
        return {"error": "not running on Windows"}

    try:
        netapi32 = ctypes.windll.netapi32
        netapi32.DsGetDcNameW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.POINTER(_DOMAIN_CONTROLLER_INFO)),
        ]
        netapi32.DsGetDcNameW.restype = ctypes.c_ulong
        netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]

        pointer = ctypes.POINTER(_DOMAIN_CONTROLLER_INFO)()
        # flags=0 -> DNS names when the domain argument is a DNS name
        rc = netapi32.DsGetDcNameW(None, domain or None, None, None, 0, ctypes.byref(pointer))
        if rc != 0:
            return {"error": rc}
        try:
            data = pointer.contents
            return {
                "dc": (data.DomainControllerName or "").lstrip("\\"),
                "address": (data.DomainControllerAddress or "").lstrip("\\"),
                "domain": data.DomainName or "",
                "forest": data.DnsForestName or "",
                "dc_site": data.DcSiteName or "",
                "client_site": data.ClientSiteName or "",
                "flags": int(data.Flags),
            }
        finally:
            if pointer:
                netapi32.NetApiBufferFree(pointer)
    except Exception as exc:  # pragma: no cover - platform dependent
        return {"error": str(exc)}


def describe_ds_flags(flags):
    names = [name for bit, name in sorted(DS_FLAGS.items()) if flags & bit]
    return ", ".join(names)


# --------------------------------------------------------------------------- #
# SMB: DC locator over RPC (dssetup + netlogon) - no code runs on the target
# --------------------------------------------------------------------------- #
MACHINE_ROLES = {
    0: "StandaloneWorkstation",
    1: "MemberWorkstation",
    2: "StandaloneServer",
    3: "MemberServer",
    4: "BackupDC/RODC",
    5: "PDC",
}

# dsgetdc.h / MS-NRPC 3.5.4.3.1 flag values
DS_RETURN_DNS_NAME = 0x40000000
DS_IP_REQUIRED = 0x00000200

LOCATOR_FLAGS = DS_RETURN_DNS_NAME | DS_IP_REQUIRED
LOCATOR_FLAGS_FALLBACK = DS_RETURN_DNS_NAME


def _strip_unc(value):
    """'\\\\dc01.corp.local' -> 'dc01.corp.local'."""
    return str(value or "").lstrip("\\").strip()


def _ndr_text(value):
    """Decode an LPWSTR field, tolerating the NULL sentinel impacket uses."""
    if value is None:
        return ""
    try:
        text = value if isinstance(value, str) else str(value)
    except Exception:
        return ""
    if text.startswith("<") and text.endswith(">"):  # sentinel repr, not a real name
        return ""
    return text.strip("\x00").strip()


def _safe_get(value, key):
    """Read a field from an impacket NDR structure/pointer without raising."""
    try:
        return value[key]
    except Exception:
        pass
    try:
        fields = getattr(value, "fields", None)
        if isinstance(fields, dict) and key in fields:
            return fields[key]
    except Exception:
        pass
    return None


def _deref_struct(value, probe="Flags"):
    """Return the struct behind an impacket NDR pointer (layout differs by version)."""
    if value is None:
        return None
    for candidate in (value, _safe_get(value, "Data")):
        if candidate is None:
            continue
        if _safe_get(candidate, probe) is not None:
            return candidate
    return value


def _union_member(value, member):
    for candidate in (value, _safe_get(value, "Data")):
        if candidate is None:
            continue
        found = _safe_get(candidate, member)
        if found is not None:
            return found
    raise KeyError(member)


def _pipe_binding(host, pipe):
    """Build the ncacn_np string binding: host + \\pipe\\<name>."""
    return rf"ncacn_np:{host}[\pipe\{str(pipe).lstrip(chr(92))}]"


def _rpc_bind(connection, pipe, interface_uuid, mode="reuse"):
    """Bind a named-pipe RPC interface through the target's SMB service.

    mode="reuse"  - ride the SMB session NetExec already authenticated (quietest)
    mode="login"  - create a second SMB session with the same credentials, so the
                    RPC layer gets real NTLM/Kerberos authentication
    """
    from impacket.dcerpc.v5 import transport

    host = getattr(connection, "host", "") or getattr(connection, "remoteName", "")
    smb_conn = getattr(connection, "conn", None)

    if mode == "reuse" and smb_conn is not None:
        rpc = transport.SMBTransport(smb_conn.getRemoteHost(), filename=pipe, smb_connection=smb_conn)
        dce = rpc.get_dce_rpc()
        if getattr(connection, "kerberos", False):
            from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE

            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
    else:
        # NOTE: SMBTransport's second positional argument is dstport, not a host.
        # The factory keeps the binding unambiguous.
        rpc = transport.DCERPCTransportFactory(_pipe_binding(host, pipe))
        rpc.set_dport(445)
        rpc.setRemoteHost(host)
        rpc.set_credentials(
            getattr(connection, "username", "") or "",
            getattr(connection, "password", "") or "",
            getattr(connection, "domain", "") or "",
            getattr(connection, "lmhash", "") or "",
            getattr(connection, "nthash", "") or "",
            getattr(connection, "aesKey", "") or "",
        )
        if getattr(connection, "kerberos", False):
            rpc.set_kerberos(True, getattr(connection, "kdcHost", None))
        dce = rpc.get_dce_rpc()

    dce.connect()
    dce.bind(interface_uuid)
    return dce


def _rpc_call(connection, pipe, interface_uuid, func):
    """Run func(dce) with automatic fallback between the two bind modes."""
    modes = []
    if getattr(connection, "conn", None) is not None:
        modes.append("reuse")
    if not getattr(connection, "kerberos", False):
        modes.append("login")
    if not modes:
        modes = ["login"]

    errors = []
    for mode in modes:
        dce = None
        try:
            dce = _rpc_bind(connection, pipe, interface_uuid, mode)
            return func(dce)
        except Exception as exc:
            errors.append(f"{mode}: {exc}")
        finally:
            # only close a transport we created ourselves: the reused SMB session
            # belongs to NetExec and must survive this module
            if dce is not None and mode == "login":
                with contextlib.suppress(Exception):
                    dce.disconnect()
    raise RuntimeError("; ".join(errors))


def rpc_domain_info(connection):
    """[MS-DSSP] DsRolerGetPrimaryDomainInformation: machine role, DNS domain, forest."""
    from impacket.dcerpc.v5 import dssp

    def call(dce):
        response = dssp.hDsRolerGetPrimaryDomainInformation(dce, 1)  # DsRolePrimaryDomainInfoBasic
        basic = _union_member(response["DomainInfo"], "DomainInfoBasic")
        role = int(_safe_get(basic, "MachineRole") or 0)
        return {
            "role": role,
            "role_name": MACHINE_ROLES.get(role, f"role {role}"),
            "domain_flat": _ndr_text(_safe_get(basic, "DomainNameFlat")),
            "domain_dns": _ndr_text(_safe_get(basic, "DomainNameDns")).strip("."),
            "forest": _ndr_text(_safe_get(basic, "DomainForestName")).strip("."),
            "flags": int(_safe_get(basic, "Flags") or 0),
        }

    return _rpc_call(connection, r"\dssetup", dssp.MSRPC_UUID_DSSP, call)


def rpc_dc_locator(connection):
    """[MS-NRPC] DsrGetDcNameEx2 (opnum 34).

    The target itself runs the DC locator (DNS SRV + LDAP ping) and returns
    DOMAIN_CONTROLLER_INFOW: DC FQDN, DC IP address, site and capability flags.
    """
    from impacket.dcerpc.v5 import nrpc

    def call(dce):
        last_error = "no response"
        for flags in (LOCATOR_FLAGS, LOCATOR_FLAGS_FALLBACK):
            try:
                response = nrpc.hDsrGetDcNameEx2(
                    dce, nrpc.NULL, nrpc.NULL, 0, nrpc.NULL, nrpc.NULL, nrpc.NULL, flags
                )
            except Exception as exc:
                last_error = str(exc)
                continue
            error = int(_safe_get(response, "ErrorCode") or 0)
            if error:
                last_error = f"ErrorCode 0x{error:08x}"
                continue
            info = _deref_struct(response["DomainControllerInfo"])
            name = _ndr_text(_safe_get(info, "DomainControllerName"))
            address = _ndr_text(_safe_get(info, "DomainControllerAddress"))
            if not name and not address:
                last_error = "DOMAIN_CONTROLLER_INFOW is empty"
                continue
            value = int(_safe_get(info, "Flags") or 0)
            return {
                "dc_name": _strip_unc(name),
                "dc_address": _strip_unc(address),
                "address_type": int(_safe_get(info, "DomainControllerAddressType") or 0),
                "domain": _ndr_text(_safe_get(info, "DomainName")).strip("."),
                "forest": _ndr_text(_safe_get(info, "DnsForestName")).strip("."),
                "site": _ndr_text(_safe_get(info, "DcSiteName")),
                "client_site": _ndr_text(_safe_get(info, "ClientSiteName")),
                "flags": value,
                "flags_text": describe_ds_flags(value),
                "request_flags": flags,
            }
        raise RuntimeError(last_error)

    return _rpc_call(connection, r"\netlogon", nrpc.MSRPC_UUID_NRPC, call)


def rpc_site_name(connection):
    """[MS-NRPC] DsrGetSiteName (opnum 28): AD site of the target itself."""
    from impacket.dcerpc.v5 import nrpc

    def call(dce):
        response = nrpc.hDsrGetSiteName(dce, nrpc.NULL)
        return _ndr_text(_safe_get(response, "SiteName"))

    return _rpc_call(connection, r"\netlogon", nrpc.MSRPC_UUID_NRPC, call)


def rpc_any_dc(connection):
    """[MS-NRPC] NetrGetAnyDCName (opnum 13): fallback when the locator is denied."""
    from impacket.dcerpc.v5 import nrpc

    def call(dce):
        response = nrpc.hNetrGetAnyDCName(dce, nrpc.NULL, nrpc.NULL)
        return _strip_unc(_ndr_text(_safe_get(response, "Buffer")))

    return _rpc_call(connection, r"\netlogon", nrpc.MSRPC_UUID_NRPC, call)


def smb_locate(connection, log=None):
    """Ask the target for its domain and for a domain controller. Never raises."""
    result = {
        "domain": "",
        "forest": "",
        "domain_flat": "",
        "role": "",
        "role_name": "",
        "target_site": "",
        "dc": {},
        "methods": [],
        "errors": [],
    }

    try:
        domain_info = rpc_domain_info(connection)
        result["domain"] = domain_info.get("domain_dns") or domain_info.get("domain_flat") or ""
        result["domain_flat"] = domain_info.get("domain_flat") or ""
        result["forest"] = domain_info.get("forest") or ""
        result["role"] = domain_info.get("role")
        result["role_name"] = domain_info.get("role_name") or ""
        result["methods"].append("dssetup")
    except Exception as exc:
        result["errors"].append(f"dssetup: {exc}")
        if log:
            log.debug(f"dcinfo: dssetup query failed: {exc}")

    try:
        result["dc"] = rpc_dc_locator(connection)
        result["methods"].append("netlogon DsrGetDcNameEx2")
    except Exception as exc:
        result["errors"].append(f"netlogon DsrGetDcNameEx2: {exc}")
        if log:
            log.debug(f"dcinfo: DsrGetDcNameEx2 failed: {exc}")
        try:
            result["dc"] = {"dc_name": rpc_any_dc(connection), "dc_address": "", "site": "", "flags": 0}
            result["methods"].append("netlogon NetrGetAnyDCName")
        except Exception as fallback_exc:
            result["errors"].append(f"netlogon NetrGetAnyDCName: {fallback_exc}")

    try:
        result["target_site"] = rpc_site_name(connection)
        result["methods"].append("netlogon DsrGetSiteName")
    except Exception as exc:
        result["errors"].append(f"netlogon DsrGetSiteName: {exc}")
        result["target_site"] = (result.get("dc") or {}).get("client_site", "")

    return result


def _merge_locator(info, locator):
    """Add the DC reported by netlogon to the DNS-derived DC list."""
    dc = (locator or {}).get("dc") or {}
    name = (dc.get("dc_name") or "").lower()
    address = dc.get("dc_address") or ""
    if not name and not address:
        return

    flags = int(dc.get("flags") or 0)
    roles = []
    if flags & 0x00000008:
        roles.append("ldap")
    if flags & 0x00000020:
        roles.append("kerberos")
    if flags & 0x00000004:
        roles.append("gc")
    if flags & 0x00000001:
        roles.append("pdc")
    if not roles:
        roles = ["ldap"]

    known = {entry["fqdn"].lower(): entry for entry in info.get("dcs") or []}
    entry = known.get(name)
    if entry is None:
        entry = {"fqdn": name or address, "port": 389, "roles": [], "addresses": []}
        info.setdefault("dcs", []).insert(0, entry)
    if address and address not in entry["addresses"]:
        entry["addresses"].insert(0, address)
    for role in roles:
        if role not in entry["roles"]:
            entry["roles"].append(role)
    if dc.get("site"):
        entry["site"] = dc["site"]
    entry["source"] = "netlogon"


# --------------------------------------------------------------------------- #
# LDAP helpers (impacket LDAPConnection, the object NetExec already holds)
# --------------------------------------------------------------------------- #
def ldap_entries(ldap_conn, base, ldap_filter, attributes, scope="subtree", size_limit=0):
    if ldap_conn is None:
        return []
    kwargs = {
        "searchBase": base,
        "searchFilter": ldap_filter,
        "attributes": list(attributes),
        "sizeLimit": size_limit,
    }
    if scope == "base":
        # impacket expects a pyasn1 enumeration; 0 == baseObject on the wire
        kwargs["scope"] = _LdapScope("baseObject") if _LdapScope is not None else 0
    try:
        answers = ldap_conn.search(**kwargs) or []
    except Exception:
        return []

    parsed = []
    for answer in answers:
        entry = _parse_entry(answer)
        if entry:
            parsed.append(entry)
    return parsed


def _parse_entry(answer):
    """Normalise an impacket SearchResultEntry into {attribute: [bytes, ...]}."""
    parsed = {}
    try:
        attributes = answer["attributes"]
    except Exception:
        return parsed

    for attribute in attributes:
        try:
            name = str(attribute["type"]).lower()
            values = []
            for value in attribute["vals"]:
                try:
                    values.append(bytes(value.asOctets()))
                except AttributeError:
                    values.append(value if isinstance(value, bytes) else str(value).encode("utf-8", "ignore"))
            parsed[name] = values
        except Exception:
            continue
    return parsed


def _text(values, default=""):
    if not values:
        return default
    raw = values[0]
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace").strip("\x00").strip()
    return str(raw).strip()


def _first(rootdse, attribute, default=""):
    return _text(rootdse.get(attribute), default)


def _debug(log, message):
    if log is None:
        return
    try:
        log.debug(message)
    except Exception:
        pass


def probe_ports(host, ports=(445, 389, 53), timeout=2.0):
    """Quick TCP reachability check: 'open' / 'closed' / '-' (no host)."""
    result = {}
    if not host:
        return result
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                result[port] = "open"
        except OSError:
            result[port] = "closed"
    return result


def get_rootdse(ldap_conn):
    """Base-scope search of the RootDSE: readable by any authenticated (even anonymous) user."""
    entries = ldap_entries(ldap_conn, "", "(objectClass=*)", ROOTDSE_ATTRIBUTES, scope="base", size_limit=1)
    return entries[0] if entries else {}


def dn_to_domain(dn):
    labels = []
    for part in (dn or "").split(","):
        part = part.strip()
        if part[:3].upper() == "DC=" and len(part) > 3:
            labels.append(part[3:])
    return ".".join(labels).lower()


def domain_to_dn(domain):
    return ",".join(f"DC={part}" for part in (domain or "").split(".") if part)


def enum_sites(ldap_conn, configuration_dn):
    """Subnet -> site mapping from CN=Subnets,CN=Sites,CN=Configuration (readable by users)."""
    if not configuration_dn:
        return []
    base = f"CN=Subnets,CN=Sites,{configuration_dn}"
    subnets = []
    for entry in ldap_entries(ldap_conn, base, "(objectClass=subnet)", ("name", "cn", "siteObject")):
        name = _text(entry.get("name")) or _text(entry.get("cn"))
        site_dn = _text(entry.get("siteobject"))
        site = ""
        first_rdn = site_dn.split(",")[0].strip() if site_dn else ""
        if first_rdn[:3].upper() == "CN=":
            site = first_rdn[3:]
        if name:
            subnets.append({"subnet": name, "site": site or site_dn})
    return subnets


def ldap_dcs(ldap_conn, configuration_dn):
    """DC list straight from CN=Sites,CN=Configuration - works without DNS at all."""
    if ldap_conn is None or not configuration_dn:
        return []
    found = []
    sites = ldap_entries(ldap_conn, f"CN=Sites,{configuration_dn}", "(objectClass=site)", ("name", "cn"))
    for site in sites:
        site_name = _text(site.get("name")) or _text(site.get("cn"))
        if not site_name:
            continue
        servers = ldap_entries(
            ldap_conn,
            f"CN=Servers,CN={site_name},CN=Sites,{configuration_dn}",
            "(objectClass=server)",
            ("name", "cn", "dNSHostName"),
        )
        for server in servers:
            fqdn = _text(server.get("dnshostname")).lower().strip(".")
            name = fqdn or _text(server.get("name")) or _text(server.get("cn"))
            if name:
                found.append({"fqdn": name, "site": site_name})
    return found


def _site_for_address(subnets, address):
    try:
        candidate = ipaddress.ip_address(address)
    except ValueError:
        return ""
    best = ""
    best_prefix = -1
    for item in subnets:
        try:
            network = ipaddress.ip_network(item["subnet"], strict=False)
        except ValueError:
            continue
        if network.version != candidate.version:
            continue
        if candidate in network and network.prefixlen > best_prefix:
            best, best_prefix = item["site"], network.prefixlen
    return best


# --- AD-integrated DNS zones (best effort, dnsRecord is a binary blob) ----- #
def _adidns_address(blob):
    """Decode an ADIDNS dnsRecord blob into ('A'|'AAAA', address) or None.

    Layout used by AD (MS-DNSP 2.2.2.2.5): the record type lives in the header and
    the RDATA is stored in DNS wire format, so for A/AAAA the address is simply the
    tail of the blob. That keeps the parser stable across Windows versions.
    """
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 8:
        return None
    blob = bytes(blob)
    for offset in (4, 2):  # different writers put the type word at 4 or 2
        if offset + 2 > len(blob):
            continue
        rtype = struct.unpack("<H", blob[offset: offset + 2])[0]
        if rtype == 1 and len(blob) >= 4:
            return "A", socket.inet_ntoa(blob[-4:])
        if rtype == 28 and len(blob) >= 16:
            return "AAAA", socket.inet_ntop(socket.AF_INET6, blob[-16:])
    return None


def enum_zones(ldap_conn, domain_dn, forest_dn, domain, limit=400):
    """Read A/AAAA records out of AD-integrated DNS zones (works for plain users)."""
    if not ldap_conn or not domain_dn:
        return [], False

    bases = [f"CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}"]
    if forest_dn and forest_dn != domain_dn:
        bases.append(f"CN=MicrosoftDNS,DC=ForestDnsZones,{forest_dn}")
    bases.append(f"CN=MicrosoftDNS,CN=System,{domain_dn}")

    zones = []
    for base in bases:
        for entry in ldap_entries(ldap_conn, base, "(objectClass=dnsZone)", ("name", "dc")):
            zone = _text(entry.get("dc")) or _text(entry.get("name"))
            if not zone or (zone, base) in zones:
                continue
            if zone != domain and not zone.endswith("." + domain):
                continue
            if ".DomainDnsZones." in zone or ".ForestDnsZones." in zone:
                continue
            zones.append((zone, base))

    records = []
    seen = set()
    truncated = False
    for zone, base in zones:
        zone_dn = f"DC={zone},{base}"
        for entry in ldap_entries(
            ldap_conn, zone_dn, "(dnsRecord=*)", ("dc", "dnsRecord"), size_limit=limit
        ):
            node = _text(entry.get("dc")) or _text(entry.get("name"))
            for blob in entry.get("dnsrecord", []):
                decoded = _adidns_address(blob)
                if not decoded:
                    continue
                rtype, address = decoded
                owner = zone if node in ("", "@") else f"{node}.{zone}"
                key = (owner.lower(), address)
                if key in seen:
                    continue
                seen.add(key)
                records.append({"name": owner, "type": rtype, "address": address})
            if len(records) >= limit:
                truncated = True
                break
        if truncated:
            break

    records.sort(key=lambda item: (item["name"].lower(), item["address"]))
    return records, truncated


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def discover(
    domain=None,
    ldap_conn=None,
    target=None,
    dns_servers=None,
    timeout=DNS_TIMEOUT,
    retries=DNS_RETRIES,
    do_sites=True,
    do_zones=False,
    zone_limit=400,
    log=None,
):
    """Collect DC information. Returns a dict, never prints and never raises."""
    info = {
        "domain": (domain or "").strip().strip("."),
        "domain_dn": "",
        "forest_dn": "",
        "configuration_dn": "",
        "target": (target or "").strip(),
        "target_fqdn": "",
        "target_addresses": [],
        "target_ptr": "",
        "ldap": ldap_conn is not None,
        "rootdse": {},
        "ldap_service": {},
        "functional_level": "",
        "dns_servers": [],
        "srv": [],
        "dcs": [],
        "sites": [],
        "site_of_dc": {},
        "zones": [],
        "zones_truncated": False,
        "sources": [],
        "warnings": [],
        "dns_errors": [],
    }

    rootdse = get_rootdse(ldap_conn) if ldap_conn is not None else {}
    info["rootdse"] = {name: [_text([value]) for value in values] for name, values in rootdse.items()}
    _debug(
        log,
        f"dcinfo: RootDSE attributes={len(rootdse)} domain_dn={_first(rootdse, 'defaultnamingcontext') or '-'} "
        f"config_dn={_first(rootdse, 'configurationnamingcontext') or '-'}",
    )

    info["domain_dn"] = _first(rootdse, "defaultnamingcontext")
    info["forest_dn"] = _first(rootdse, "rootdomainnamingcontext") or info["domain_dn"]
    info["configuration_dn"] = _first(rootdse, "configurationnamingcontext")
    info["target_fqdn"] = _first(rootdse, "dnshostname").lower()

    service = _first(rootdse, "ldapservicename")
    if service:
        service_part, _, realm = service.partition("@")
        service_domain, _, account = service_part.partition(":")
        info["ldap_service"] = {
            "domain": service_domain.lower(),
            "account": account.rstrip("$"),
            "realm": realm.lower(),
        }

    if not info["domain"] and info["domain_dn"]:
        info["domain"] = dn_to_domain(info["domain_dn"])
    if info["domain"] and "." not in info["domain"]:
        # NetBIOS name was supplied: prefer the DNS domain from LDAP if we have it
        candidate = info["ldap_service"].get("domain") or dn_to_domain(info["domain_dn"])
        if candidate and "." in candidate:
            info["warnings"].append(f"domain '{info['domain']}' looks like a NetBIOS name, using '{candidate}'")
            info["domain"] = candidate
    if info["domain"] and not info["domain_dn"]:
        info["domain_dn"] = domain_to_dn(info["domain"])
    if info["domain"] and "." not in info["domain"]:
        info["warnings"].append(
            f"'{info['domain']}' has no DNS suffix, SRV lookups will fail: pass DOMAIN=corp.local"
        )
    if not info["forest_dn"]:
        info["forest_dn"] = info["domain_dn"]
    if not info["configuration_dn"] and info["domain_dn"]:
        info["configuration_dn"] = f"CN=Configuration,{info['domain_dn']}"

    level = _first(rootdse, "domaincontrollerfunctionality")
    if level.isdigit():
        info["functional_level"] = FUNCTIONAL_LEVELS.get(int(level), f"level {level}")

    # DNS servers: explicit option wins, otherwise the machine we talk to + the OS list
    candidates = [str(server).strip() for server in (dns_servers or [])]
    if not candidates:
        candidates.append(info["target"])
        if info["target_fqdn"]:
            candidates.append(info["target_fqdn"])
        candidates.extend(system_context()["dns"])

    resolver = DNSResolver(candidates, timeout=timeout, retries=retries)
    info["dns_servers"] = list(resolver.servers)
    _debug(log, f"dcinfo: DNS servers to try: {', '.join(info['dns_servers']) or '-'}")

    if info["target"]:
        info["target_addresses"] = resolver.addresses(info["target"])
        if not info["target_addresses"] and info["target_fqdn"]:
            info["target_addresses"] = resolver.addresses(info["target_fqdn"])
    if not info["target_fqdn"] and info["target_addresses"]:
        info["target_ptr"] = resolver.ptr(info["target_addresses"][0])
        if info["target_ptr"]:
            info["target_fqdn"] = info["target_ptr"].lower()

    if not info["domain"]:
        info["warnings"].append("domain is unknown: pass -o DOMAIN=corp.local or --domain corp.local")
        return info

    if do_sites:
        info["sites"] = enum_sites(ldap_conn, info["configuration_dn"])

    # Locate DCs through DNS SRV records
    for template, role in SRV_TEMPLATES:
        query = template.format(domain=info["domain"])
        records = resolver.srv(query)
        if records:
            info["srv"].append({"query": query, "role": role, "records": records})
        _debug(log, f"dcinfo: SRV {query} -> {len(records)} record(s)")
    for site in sorted({item["site"] for item in info["sites"] if item["site"]}):
        query = f"_ldap._tcp.{site}._sites.dc._msdcs.{info['domain']}"
        records = resolver.srv(query)
        if records:
            info["srv"].append({"query": query, "role": "ldap", "records": records})

    dcs = {}
    for group in info["srv"]:
        role = group["role"]
        for record in group["records"]:
            fqdn = record["target"]
            entry = dcs.setdefault(
                fqdn,
                {"fqdn": fqdn, "port": record["port"], "roles": [], "addresses": []},
            )
            if role not in entry["roles"]:
                entry["roles"].append(role)
            entry["port"] = min(entry["port"], record["port"])

    if not dcs and ldap_conn is not None:
        # DNS is unavailable, but the directory itself knows every DC and its site
        for item in ldap_dcs(ldap_conn, info["configuration_dn"]):
            entry = dcs.setdefault(
                item["fqdn"],
                {"fqdn": item["fqdn"], "port": 389, "roles": ["ldap"], "addresses": []},
            )
            entry["site"] = entry.get("site") or item["site"]
            entry["source"] = "ldap"
        if dcs:
            _debug(log, f"dcinfo: DC list recovered from CN=Sites/CN=Servers: {len(dcs)}")
            info["sources"].append("LDAP CN=Sites")

    for entry in dcs.values():
        entry["addresses"] = resolver.addresses(entry["fqdn"])
        entry.setdefault("site", "")
        for address in entry["addresses"]:
            site = _site_for_address(info["sites"], address)
            if site:
                entry["site"] = site
                info["site_of_dc"][address] = site
                break
    info["dcs"] = sorted(dcs.values(), key=lambda item: item["fqdn"])

    if not info["dcs"]:
        tried = ", ".join(info["dns_servers"]) or "no DNS server"
        info["warnings"].append(
            f"no _ldap._tcp.dc._msdcs SRV records from {tried}: the DC locator still returned a DC, "
            "but the full DC list needs a DNS server that holds the AD zone (try -o DNS=<dns server ip>)"
        )

    if do_zones and ldap_conn is not None:
        info["zones"], info["zones_truncated"] = enum_zones(
            ldap_conn, info["domain_dn"], info["forest_dn"], info["domain"], limit=zone_limit
        )

    info["dns_errors"] = list(dict.fromkeys(resolver.errors))[:10]
    return info


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _print_report(log, info, show_zones=True):
    domain = (info.get("domain") or "?").upper()
    if info.get("smb"):
        log.highlight(f"DC discovery for {domain}  (SMB/RPC, no admin rights, nothing executed on target)")
    else:
        log.highlight(f"DC discovery for {domain}  (LDAP + DNS only, no admin rights)")

    if info.get("domain_dn"):
        log.display(f"  domain DN          : {info['domain_dn']}")
    if info.get("forest_dn") and info["forest_dn"] != info.get("domain_dn"):
        log.display(f"  forest DN          : {info['forest_dn']}")
    if info.get("functional_level"):
        log.display(f"  functional level   : {info['functional_level']}")

    account = info.get("ldap_service", {}).get("account")
    if account:
        log.display(f"  LDAP service       : {account}$")

    if info.get("target"):
        addresses = ",".join(info.get("target_addresses") or []) or "?"
        fqdn = info.get("target_fqdn") or info.get("target_ptr") or ""
        log.display(f"  target             : {info['target']} -> {fqdn or '-'} [{addresses}]")

    if info.get("dns_servers"):
        log.display(f"  DNS servers used   : {', '.join(info['dns_servers'])}")
    if info.get("sources"):
        log.display(f"  DC list source     : {', '.join(info['sources'])}")
    if info.get("reachability"):
        states = " ".join(f"{port}={state}" for port, state in sorted(info["reachability"].items()))
        log.display(f"  DC reachability    : {states}")

    smb = info.get("smb") or {}
    locator = (info.get("locator") or {}).get("dc") or {}

    if smb:
        log.display(f"  discovery channel  : SMB/RPC via {smb.get('channel') or '-'}")
        log.display(f"  target role        : {smb.get('role') or '?'}  site={smb.get('target_site') or '-'}")

    if locator.get("dc_name") or locator.get("dc_address"):
        log.success(
            f"DC from target locator: {locator.get('dc_name') or '?'} "
            f"[{locator.get('dc_address') or '?'}] site={locator.get('site') or '-'} "
            f"flags={locator.get('flags_text') or '-'}"
        )

    dcs = info.get("dcs") or []
    if dcs:
        log.success(f"Domain controllers found: {len(dcs)}")
        for entry in dcs:
            addresses = ",".join(entry["addresses"]) or "?"
            roles = ",".join(entry["roles"]) or "-"
            site = entry.get("site") or "-"
            log.success(
                f"  DC {entry['fqdn']} [{addresses}] site={site} roles={roles}"
            )
    else:
        log.fail("No domain controllers found through DNS SRV records")

    if info.get("srv"):
        log.highlight("  SRV records")
        for group in info["srv"]:
            log.display(f"    {group['query']}")
            for record in group["records"]:
                log.display(
                    f"      {record['target']}:{record['port']}  priority={record['priority']} weight={record['weight']}"
                )

    if info.get("sites"):
        log.highlight("  Sites (CN=Sites,CN=Configuration)")
        for item in sorted(info["sites"], key=lambda value: (value["site"], value["subnet"])):
            log.display(f"    {item['site']:<28} {item['subnet']}")

    zones = info.get("zones") or []
    if show_zones and zones:
        suffix = " (truncated)" if info.get("zones_truncated") else ""
        log.highlight(f"  A/AAAA records from AD-integrated DNS zones{suffix}")
        for record in zones:
            log.display(f"    {record['name']:<40} {record['address']}")

    for warning in info.get("warnings") or []:
        log.fail(f"  warning: {warning}")
    for error in info.get("dns_errors") or []:
        log.debug(f"  DNS query failed: {error}")


class _VerboseLog:
    """Turn log.debug() into visible output when -o DEBUG=True is used."""

    def __init__(self, log):
        self._log = log

    def debug(self, message):
        self._log.display(f"[debug] {message}")

    def __getattr__(self, name):
        return getattr(self._log, name)


class _ConsoleLogger:
    """Minimal stand-in for NetExec's logger so the CLI can reuse the reporting code."""

    def highlight(self, message):
        print(f"[*] {message}")

    def display(self, message):
        print(f"    {message}")

    def success(self, message):
        print(f"[+] {message}")

    def fail(self, message):
        print(f"[-] {message}")

    def debug(self, message):
        if os.environ.get("DCINFO_DEBUG"):
            print(f"[d] {message}")


# --------------------------------------------------------------------------- #
# NetExec module
# --------------------------------------------------------------------------- #
class NXCModule:
    """Domain controller locator (IP / DNS name / site) that needs no admin rights."""

    name = "dcinfo"
    description = "Find DC IP/DNS name/site over SMB (netlogon DsrGetDcNameEx2) or LDAP - no admin, no nslookup"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.domain = None
        self.dns_servers = []
        self.timeout = DNS_TIMEOUT
        self.retries = DNS_RETRIES
        self.sites = True
        self.zones = False
        self.zone_limit = 400
        self.use_ldap = True
        self.debug = False

    def options(self, context, module_options):
        """DOMAIN     Domain DNS name (default: taken from the target's RPC/LDAP data).
        DNS        Comma separated DNS servers to query (default: DC address + system resolvers).
        SITES      Enumerate sites/subnets from CN=Sites (default: True).
        ZONES      Also read A/AAAA records from AD-integrated DNS zones (default: False).
        LDAP       SMB path only: enrich with LDAP reads (RootDSE/sites/zones, default: True).
        TIMEOUT    Per-query DNS timeout in seconds (default: 2).
        RETRIES    DNS retries per server (default: 2).
        ZONE_LIMIT Maximum number of DNS records with ZONES=True (default: 400).
        DEBUG      Print every discovery step (default: False).
        """
        for key, value in (module_options or {}).items():
            key = str(key).upper()
            value = "" if value is None else str(value).strip()
            try:
                if key == "DOMAIN":
                    self.domain = value.strip(".") or None
                elif key == "DNS":
                    self.dns_servers = [item.strip() for item in value.split(",") if item.strip()]
                elif key == "SITES":
                    self.sites = value.lower() not in ("0", "false", "no", "off")
                elif key == "ZONES":
                    self.zones = value.lower() in ("1", "true", "yes", "y", "on")
                elif key == "LDAP":
                    self.use_ldap = value.lower() not in ("0", "false", "no", "off")
                elif key == "TIMEOUT":
                    self.timeout = float(value)
                elif key == "RETRIES":
                    self.retries = max(1, int(value))
                elif key == "ZONE_LIMIT":
                    self.zone_limit = max(1, int(value))
                elif key == "DEBUG":
                    self.debug = value.lower() in ("1", "true", "yes", "y", "on")
            except ValueError:
                context.log.fail(f"dcinfo: ignoring invalid value for {key}: {value!r}")

    def on_login(self, context, connection):
        try:
            if getattr(connection, "ldap_connection", None) is not None:
                self._on_ldap(context, connection)
            else:
                self._on_smb(context, connection)
        except Exception as exc:  # never break the NetExec run
            context.log.fail(f"dcinfo: discovery failed: {exc}")

    # -- SMB: the target itself performs the DC lookup ---------------------- #
    def _on_smb(self, context, connection):
        log = _VerboseLog(context.log) if self.debug else context.log
        locator = smb_locate(connection, log)
        domain = self.domain or locator.get("domain") or getattr(connection, "domain", "") or ""
        dc_address = (locator.get("dc") or {}).get("dc_address") or ""

        reach = probe_ports(dc_address, (53, 389, 445), self.timeout) if dc_address else {}
        if reach:
            log.debug(f"dcinfo: DC {dc_address} reachability: {reach}")

        ldap_conn = None
        if self.use_ldap and reach.get(389) == "open":
            try:
                ldap_conn = _connect_ldap(
                    dc_address,
                    domain,
                    getattr(connection, "username", ""),
                    getattr(connection, "password", ""),
                    getattr(connection, "lmhash", ""),
                    getattr(connection, "nthash", ""),
                    timeout=10,
                )
                log.debug(f"dcinfo: LDAP bind to {dc_address} ok")
            except Exception as exc:
                log.debug(f"dcinfo: LDAP enrichment skipped: {exc}")

        if self.dns_servers:
            dns_targets = self.dns_servers
        elif reach.get(53) == "open":
            dns_targets = [dc_address]
        else:
            dns_targets = None

        info = discover(
            domain=domain,
            ldap_conn=ldap_conn,
            target=getattr(connection, "host", "") or "",
            dns_servers=dns_targets,
            timeout=self.timeout,
            retries=self.retries,
            do_sites=self.sites and ldap_conn is not None,
            do_zones=self.zones and ldap_conn is not None,
            zone_limit=self.zone_limit,
            log=log,
        )
        info["reachability"] = reach
        if reach and reach.get(53) != "open" and reach.get(389) != "open":
            info["warnings"].append(
                f"DC {dc_address} is not reachable from this host on 53/389: "
                "only the locator answer is shown (it still is the DC IP and DNS name)"
            )
        info["locator"] = locator
        info["smb"] = {
            "target": getattr(connection, "host", "") or "",
            "role": locator.get("role_name") or "",
            "target_site": locator.get("target_site") or "",
            "channel": " + ".join(locator.get("methods") or []) or "-",
        }
        if domain and not info.get("domain"):
            info["domain"] = domain
        _merge_locator(info, locator)
        _print_report(context.log, info)

    # -- LDAP: RootDSE + DNS SRV (previous behaviour) ----------------------- #
    def _on_ldap(self, context, connection):
        log = _VerboseLog(context.log) if self.debug else context.log
        ldap_conn = getattr(connection, "ldap_connection", None)
        domain = self.domain or getattr(connection, "domain", "") or ""
        target = getattr(connection, "host", "") or getattr(connection, "target", "") or ""

        info = discover(
            domain=domain,
            ldap_conn=ldap_conn,
            target=target,
            dns_servers=self.dns_servers,
            timeout=self.timeout,
            retries=self.retries,
            do_sites=self.sites,
            do_zones=self.zones,
            zone_limit=self.zone_limit,
            log=log,
        )
        _print_report(context.log, info)

        for entry in info.get("dcs") or []:
            context.log.debug(f"dcinfo: {entry['fqdn']} {entry['addresses']} {entry['roles']}")


# --------------------------------------------------------------------------- #
# Standalone CLI
# --------------------------------------------------------------------------- #
def _connect_ldap(dc, domain, user=None, password=None, lmhash=None, nthash=None, timeout=15):
    """Create an impacket LDAP connection for standalone use."""
    from impacket.ldap.ldap import LDAPConnection

    connection = LDAPConnection(f"ldap://{dc}", baseDN="", timeout=timeout)
    if user:
        connection.login(user, password or "", domain or "", lmhash or "", nthash or "")
    return connection


def _parse_args(argv):
    import argparse

    parser = argparse.ArgumentParser(
        prog="dcinfo",
        description="Find AD domain controllers (IP, DNS name, site) with LDAP and DNS only. "
        "No admin rights, no nslookup/nltest, no remote execution.",
    )
    parser.add_argument("--domain", help="AD DNS domain, e.g. corp.local")
    parser.add_argument("--dc", help="DC to query (IP or FQDN); default: local DC locator or DNS SRV")
    parser.add_argument("--dns", help="comma separated DNS servers to query")
    parser.add_argument("--user", help="domain user for authenticated LDAP reads (RootDSE works anonymously too)")
    parser.add_argument("--password", help="password for --user")
    parser.add_argument("--zones", action="store_true", help="also dump A/AAAA records from AD-integrated DNS zones")
    parser.add_argument("--no-sites", action="store_true", help="skip CN=Sites subnets enumeration")
    parser.add_argument("--timeout", type=float, default=DNS_TIMEOUT, help="per-query DNS timeout")
    parser.add_argument("--local", action="store_true", help="ask the local OS for the DC first (Windows DsGetDcName)")
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    log = _ConsoleLogger()

    domain = (args.domain or "").strip().strip(".")
    target = (args.dc or "").strip()
    local = None

    if args.local or not target:
        local = windows_dc_info(domain or None)
        if "error" in local:
            if os.name == "nt":
                log.debug(f"DsGetDcName failed: {local['error']}")
        else:
            log.success(
                f"Local DC locator: {local['dc']} [{local['address']}] "
                f"site={local['dc_site'] or '-'} flags={describe_ds_flags(local['flags']) or '-'}"
            )
            domain = domain or (local.get("domain") or "").strip(".")
            target = target or local.get("address", "")
            if local.get("client_site"):
                log.display(f"  client site        : {local['client_site']}")

    context = system_context()
    domain = domain or context["domain"]

    ldap_conn = None
    if target and args.user:
        try:
            ldap_conn = _connect_ldap(target, domain, args.user, args.password)
        except Exception as exc:
            log.fail(f"LDAP bind to {target} failed: {exc}")

    if target and not domain:
        # anonymous RootDSE still tells us the domain DN even without credentials
        try:
            probe = _connect_ldap(target, "")
            rootdse = get_rootdse(probe)
            domain = dn_to_domain(_first(rootdse, "defaultnamingcontext"))
            if not domain:
                service = _first(rootdse, "ldapservicename")
                domain = service.partition("@")[0].partition(":")[0]
            ldap_conn = ldap_conn or probe
        except Exception as exc:
            log.debug(f"anonymous RootDSE probe failed: {exc}")

    if not domain:
        log.fail("domain is unknown: pass --domain corp.local (or run with --local on a domain-joined host)")
        return 2

    dns_servers = [item.strip() for item in (args.dns or "").split(",") if item.strip()]
    if not dns_servers:
        dns_servers = None  # discover() falls back to "target + system resolvers"

    info = discover(
        domain=domain,
        ldap_conn=ldap_conn,
        target=target,
        dns_servers=dns_servers,
        timeout=args.timeout,
        do_sites=not args.no_sites,
        do_zones=args.zones,
    )
    _print_report(log, info, show_zones=args.zones)

    if not target:
        log.fail("hint: give --dc <dc ip> to enrich the output with LDAP data")
    return 0 if info.get("dcs") else 1


if __name__ == "__main__":
    sys.exit(main())
