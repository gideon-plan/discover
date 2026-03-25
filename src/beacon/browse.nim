## browse.nim -- Discover SP endpoints on local network.

{.experimental: "strict_funcs".}

import basis/code/choice, mdns, dnssd

# =====================================================================================================================
# Types
# =====================================================================================================================

type
  DiscoveredService* = object
    info*: ServiceInfo
    source_addr*: string

  BrowseFn* = proc(query_packet: string): Choice[seq[string]] {.raises: [].}
    ## Send mDNS query, return response packets.

# =====================================================================================================================
# Browse
# =====================================================================================================================

proc make_browse_query*(service_type: string, domain: string = "local"): string =
  ## Create an mDNS query packet for DNS-SD service browsing.
  let pkt = DnsPacket(
    header: DnsHeader(flags: 0, qd_count: 1),
    questions: @[DnsQuestion(name: service_type & "." & domain,
                             qtype: TypePTR, qclass: ClassIN)])
  encode_packet(pkt)

proc parse_browse_response*(response: string): Choice[seq[ServiceInfo]] =
  ## Parse an mDNS response for discovered services.
  let pkt = decode_packet(response)
  if pkt.is_bad:
    return bad[seq[ServiceInfo]](pkt.err)
  var services: seq[ServiceInfo]
  for ans in pkt.val.answers:
    if ans.rtype == TypePTR:
      # PTR record points to service instance name
      var pos = 0
      let instance_name = try: decode_name(ans.rdata, pos)
                          except DiscoverError: continue
      services.add(ServiceInfo(name: instance_name))
  # Enrich with SRV/TXT from additional records
  for rec in pkt.val.additional:
    if rec.rtype == TypeTXT:
      for i in 0 ..< services.len:
        if services[i].name == rec.name:
          services[i].txt = decode_txt(rec.rdata)
  good(services)
