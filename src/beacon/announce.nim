## announce.nim -- Advertise SP listener as mDNS service.

{.experimental: "strict_funcs".}

import mdns, dnssd

# =====================================================================================================================
# Announcement
# =====================================================================================================================

proc make_announcement*(service: ServiceInfo, ttl: uint32 = 120): string =
  ## Create an mDNS announcement packet for the service.
  var answers: seq[DnsRecord]
  # PTR record: browse_name -> full_name
  answers.add(DnsRecord(name: browse_name(service), rtype: TypePTR,
                        rclass: ClassIN, ttl: ttl,
                        rdata: encode_name(full_name(service))))
  # SRV record
  answers.add(DnsRecord(name: full_name(service), rtype: TypeSRV,
                        rclass: ClassIN, ttl: ttl,
                        rdata: encode_srv(0, 0, service.port, service.host)))
  # TXT record
  if service.txt.len > 0:
    answers.add(DnsRecord(name: full_name(service), rtype: TypeTXT,
                          rclass: ClassIN, ttl: ttl,
                          rdata: encode_txt(service.txt)))
  let pkt = DnsPacket(
    header: DnsHeader(flags: 0x8400, an_count: uint16(answers.len)),  # response + authoritative
    answers: answers)
  encode_packet(pkt)

proc make_goodbye*(service: ServiceInfo): string =
  ## Create a goodbye packet (TTL=0) to deregister the service.
  make_announcement(service, ttl = 0)
