## dnssd.nim -- DNS-SD service registration and browsing (RFC 6763).

{.experimental: "strict_funcs".}

import std/strutils
import mdns

# =====================================================================================================================
# Types
# =====================================================================================================================

type
  ServiceInfo* = object
    name*: string         ## e.g. "My SP Node"
    service_type*: string ## e.g. "_sp._tcp"
    domain*: string       ## e.g. "local"
    host*: string         ## e.g. "myhost.local"
    port*: uint16
    txt*: seq[(string, string)]  ## key=value TXT records

# =====================================================================================================================
# Service construction
# =====================================================================================================================

proc new_service*(name, service_type: string, port: uint16,
                  host: string = "", domain: string = "local",
                  txt: seq[(string, string)] = @[]): ServiceInfo =
  ServiceInfo(name: name, service_type: service_type, domain: domain,
              host: if host.len > 0: host else: name & "." & domain,
              port: port, txt: txt)

proc full_name*(s: ServiceInfo): string =
  ## Full DNS-SD service instance name.
  s.name & "." & s.service_type & "." & s.domain

proc browse_name*(s: ServiceInfo): string =
  ## Browse query name.
  s.service_type & "." & s.domain

# =====================================================================================================================
# TXT record encoding
# =====================================================================================================================

proc encode_txt*(pairs: seq[(string, string)]): string =
  ## Encode TXT records as length-prefixed key=value strings.
  for (k, v) in pairs:
    let entry = k & "=" & v
    result.add(char(entry.len))
    result.add(entry)

proc decode_txt*(data: string): seq[(string, string)] =
  ## Decode TXT record data into key=value pairs.
  var pos = 0
  while pos < data.len:
    let length = int(uint8(data[pos]))
    inc pos
    if pos + length > data.len: break
    let entry = data[pos ..< pos + length]
    pos += length
    let eq = entry.find('=')
    if eq >= 0:
      result.add((entry[0 ..< eq], entry[eq + 1 ..< entry.len]))
    else:
      result.add((entry, ""))

# =====================================================================================================================
# SRV record encoding
# =====================================================================================================================

proc encode_srv*(priority, weight, port: uint16, target: string): string =
  ## Encode an SRV record rdata.
  proc u16be(v: uint16): string =
    result = newString(2)
    result[0] = char(v shr 8); result[1] = char(v and 0xFF)
  u16be(priority) & u16be(weight) & u16be(port) & encode_name(target)
