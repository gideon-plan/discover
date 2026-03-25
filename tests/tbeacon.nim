## tdiscover.nim -- Tests for mDNS/DNS-SD service discovery.
{.experimental: "strict_funcs".}
import std/[unittest, strutils]
import beacon

suite "mdns":
  test "encode/decode DNS name":
    let encoded = encode_name("_sp._tcp.local")
    check encoded.len > 0
    check encoded[^1] == '\x00'
    var pos = 0
    let decoded = decode_name(encoded, pos)
    check decoded == "_sp._tcp.local"

  test "header encode/decode round-trip":
    let h = DnsHeader(id: 0, flags: 0x8400, qd_count: 1, an_count: 0)
    let encoded = encode_header(h)
    check encoded.len == 12
    var pos = 0
    let decoded = decode_header(encoded, pos)
    check decoded.flags == 0x8400
    check decoded.qd_count == 1

  test "question encode/decode round-trip":
    let q = DnsQuestion(name: "test.local", qtype: TypeA, qclass: ClassIN)
    let encoded = encode_question(q)
    var pos = 0
    let decoded = decode_question(encoded, pos)
    check decoded.name == "test.local"
    check decoded.qtype == TypeA

  test "full packet encode/decode":
    let pkt = DnsPacket(
      header: DnsHeader(qd_count: 1),
      questions: @[DnsQuestion(name: "test.local", qtype: TypeA, qclass: ClassIN)])
    let encoded = encode_packet(pkt)
    let decoded = decode_packet(encoded)
    check decoded.is_good
    check decoded.val.questions.len == 1
    check decoded.val.questions[0].name == "test.local"

suite "dnssd":
  test "service construction":
    let svc = new_service("mynode", "_sp._tcp", 5555)
    check svc.name == "mynode"
    check svc.port == 5555
    check full_name(svc) == "mynode._sp._tcp.local"
    check browse_name(svc) == "_sp._tcp.local"

  test "txt encode/decode round-trip":
    let pairs = @[("transport", "tcp"), ("port", "5555")]
    let encoded = encode_txt(pairs)
    let decoded = decode_txt(encoded)
    check decoded.len == 2
    check decoded[0] == ("transport", "tcp")
    check decoded[1] == ("port", "5555")

suite "browse":
  test "make browse query":
    let query = make_browse_query("_sp._tcp")
    check query.len > 0

suite "announce":
  test "make announcement":
    let svc = new_service("node1", "_sp._tcp", 5555, txt = @[("ver", "1")])
    let pkt = make_announcement(svc)
    check pkt.len > 0

  test "make goodbye":
    let svc = new_service("node1", "_sp._tcp", 5555)
    let pkt = make_goodbye(svc)
    check pkt.len > 0
