## mdns.nim -- mDNS packet encode/decode (RFC 6762).

{.experimental: "strict_funcs".}

import std/strutils
import basis/code/choice

type
  DiscoverError* = object of CatchableError

# =====================================================================================================================
# DNS record types
# =====================================================================================================================

const
  TypeA*     = 1'u16
  TypeAAAA*  = 28'u16
  TypeSRV*   = 33'u16
  TypeTXT*   = 16'u16
  TypePTR*   = 12'u16
  ClassIN*   = 1'u16
  MdnsPort*  = 5353
  MdnsAddr*  = "224.0.0.251"

type
  DnsHeader* = object
    id*: uint16
    flags*: uint16
    qd_count*: uint16
    an_count*: uint16
    ns_count*: uint16
    ar_count*: uint16

  DnsQuestion* = object
    name*: string
    qtype*: uint16
    qclass*: uint16

  DnsRecord* = object
    name*: string
    rtype*: uint16
    rclass*: uint16
    ttl*: uint32
    rdata*: string

  DnsPacket* = object
    header*: DnsHeader
    questions*: seq[DnsQuestion]
    answers*: seq[DnsRecord]
    authority*: seq[DnsRecord]
    additional*: seq[DnsRecord]

# =====================================================================================================================
# Name encoding
# =====================================================================================================================

proc encode_name*(name: string): string =
  ## Encode a DNS name as length-prefixed labels.
  for label in name.split('.'):
    result.add(char(label.len))
    result.add(label)
  result.add('\x00')

proc decode_name*(buf: string, pos: var int): string {.raises: [DiscoverError].} =
  ## Decode a DNS name from wire format.
  while pos < buf.len:
    let length = int(uint8(buf[pos]))
    if length == 0:
      inc pos; break
    if (length and 0xC0) == 0xC0:
      # Compression pointer
      let offset = int((uint16(uint8(buf[pos])) and 0x3F) shl 8 or uint16(uint8(buf[pos+1])))
      pos += 2
      var ptr_pos = offset
      if result.len > 0: result.add('.')
      result.add(decode_name(buf, ptr_pos))
      return
    inc pos
    if pos + length > buf.len:
      raise newException(DiscoverError, "name extends beyond buffer")
    if result.len > 0: result.add('.')
    result.add(buf[pos ..< pos + length])
    pos += length

# =====================================================================================================================
# Header encode/decode
# =====================================================================================================================

proc encode_u16_be(v: uint16): string =
  result = newString(2)
  result[0] = char(v shr 8); result[1] = char(v and 0xFF)

proc decode_u16_be(buf: string, pos: var int): uint16 {.raises: [DiscoverError].} =
  if pos + 2 > buf.len: raise newException(DiscoverError, "unexpected end")
  result = uint16(uint8(buf[pos])) shl 8 or uint16(uint8(buf[pos+1]))
  pos += 2

proc decode_u32_be(buf: string, pos: var int): uint32 {.raises: [DiscoverError].} =
  if pos + 4 > buf.len: raise newException(DiscoverError, "unexpected end")
  result = uint32(uint8(buf[pos])) shl 24 or uint32(uint8(buf[pos+1])) shl 16 or
           uint32(uint8(buf[pos+2])) shl 8 or uint32(uint8(buf[pos+3]))
  pos += 4

proc encode_header*(h: DnsHeader): string =
  encode_u16_be(h.id) & encode_u16_be(h.flags) &
  encode_u16_be(h.qd_count) & encode_u16_be(h.an_count) &
  encode_u16_be(h.ns_count) & encode_u16_be(h.ar_count)

proc decode_header*(buf: string, pos: var int): DnsHeader {.raises: [DiscoverError].} =
  result.id = decode_u16_be(buf, pos)
  result.flags = decode_u16_be(buf, pos)
  result.qd_count = decode_u16_be(buf, pos)
  result.an_count = decode_u16_be(buf, pos)
  result.ns_count = decode_u16_be(buf, pos)
  result.ar_count = decode_u16_be(buf, pos)

# =====================================================================================================================
# Question/Record encode/decode
# =====================================================================================================================

proc encode_question*(q: DnsQuestion): string =
  encode_name(q.name) & encode_u16_be(q.qtype) & encode_u16_be(q.qclass)

proc decode_question*(buf: string, pos: var int): DnsQuestion {.raises: [DiscoverError].} =
  result.name = decode_name(buf, pos)
  result.qtype = decode_u16_be(buf, pos)
  result.qclass = decode_u16_be(buf, pos)

proc encode_record*(r: DnsRecord): string =
  var enc_u32 = newString(4)
  enc_u32[0] = char((r.ttl shr 24) and 0xFF); enc_u32[1] = char((r.ttl shr 16) and 0xFF)
  enc_u32[2] = char((r.ttl shr 8) and 0xFF); enc_u32[3] = char(r.ttl and 0xFF)
  encode_name(r.name) & encode_u16_be(r.rtype) & encode_u16_be(r.rclass) &
  enc_u32 & encode_u16_be(uint16(r.rdata.len)) & r.rdata

proc decode_record*(buf: string, pos: var int): DnsRecord {.raises: [DiscoverError].} =
  result.name = decode_name(buf, pos)
  result.rtype = decode_u16_be(buf, pos)
  result.rclass = decode_u16_be(buf, pos)
  result.ttl = decode_u32_be(buf, pos)
  let rdlength = int(decode_u16_be(buf, pos))
  if pos + rdlength > buf.len:
    raise newException(DiscoverError, "rdata extends beyond buffer")
  result.rdata = buf[pos ..< pos + rdlength]
  pos += rdlength

# =====================================================================================================================
# Full packet encode/decode
# =====================================================================================================================

proc encode_packet*(pkt: DnsPacket): string =
  result = encode_header(pkt.header)
  for q in pkt.questions: result.add(encode_question(q))
  for r in pkt.answers: result.add(encode_record(r))
  for r in pkt.authority: result.add(encode_record(r))
  for r in pkt.additional: result.add(encode_record(r))

proc decode_packet*(buf: string): Choice[DnsPacket] =
  var pos = 0
  var pkt: DnsPacket
  try:
    pkt.header = decode_header(buf, pos)
    for i in 0 ..< int(pkt.header.qd_count):
      pkt.questions.add(decode_question(buf, pos))
    for i in 0 ..< int(pkt.header.an_count):
      pkt.answers.add(decode_record(buf, pos))
    for i in 0 ..< int(pkt.header.ns_count):
      pkt.authority.add(decode_record(buf, pos))
    for i in 0 ..< int(pkt.header.ar_count):
      pkt.additional.add(decode_record(buf, pos))
  except DiscoverError as e:
    return bad[DnsPacket]("discover", e.msg)
  good(pkt)
