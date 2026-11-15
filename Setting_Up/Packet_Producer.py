import argparse
import datetime
import struct
import sys

#placeholder network variables
SRC_MAC = bytes.fromhex("001122334455")
SRC_IP = (10, 0, 0, 1)
DST_IP = (233, 54, 12, 1)
SRC_PORT = 40000
DST_PORT = 26477


MOLD_HEADER_LEN = 20
PCAP_NS_MAGIC = 0xA1B23C4D
LINKTYPE_ETHERNET = 1


def read_messages(f, skip, limit):
    index = 0
    yielded = 0
    while limit == 0 or yielded < limit:
        prefix = f.read(2)
        if len(prefix) < 2:
            return
        length = struct.unpack(">H", prefix)[0]
        msg = f.read(length)
        if length == 0 or len(msg) < length:
            print(f"-- bad or truncated message after {index} messages "
                  f"(length={length}); wrong file or framing? --")
            return
        index += 1
        if index <= skip:
            continue
        yielded += 1
        yield msg


def itch_timestamp_ns(msg):
    if len(msg) < 11:
        return 0
    return int.from_bytes(msg[5:11], "big")

def build_mold_packet(session, seq, msgs):
    header = session + struct.pack(">QH", seq, len(msgs))
    blocks = b"".join(struct.pack(">H", len(m)) + m for m in msgs)
    return header + blocks

def ip_checksum(header):
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def multicast_mac(ip):
    return bytes([0x01, 0x00, 0x5E, ip[1] & 0x7F, ip[2], ip[3]])

def build_frame(payload, ident):
    udp = struct.pack(">HHHH", SRC_PORT, DST_PORT, 8 + len(payload), 0) + payload
    ip_no_sum = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp),
                            ident & 0xFFFF, 0x4000, 16, 17, 0,
                            bytes(SRC_IP), bytes(DST_IP))
    csum = ip_checksum(ip_no_sum)
    ip = ip_no_sum[:10] + struct.pack(">H", csum) + ip_no_sum[12:]
    eth = multicast_mac(DST_IP) + SRC_MAC + struct.pack(">H", 0x0800)
    return eth + ip + udp

def main():
    ap = argparse.ArgumentParser(description="ITCH 5.0 file -> MoldUDP64 packets")
    ap.add_argument("path", nargs="?", default=None)
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("-n", "--count", type=int, default=None)
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--per-packet", type=int, default=1)
    ap.add_argument("--max-payload", type=int, default=1400)
    ap.add_argument("--session", default="NASDAQ0001")
    ap.add_argument("--start-seq", type=int, default=1)
    ap.add_argument("--date", default="2019-01-30")
    ap.add_argument("--format", choices=["pcap", "hex", "both"], default="both")
    args = ap.parse_args()

    # No path on the command line (e.g. pressing Run in PyCharm): ask.
    if not args.path:
        args.path = "" #put your file path to the extracted file here
        out = input("Output name without extension [itch_packets]: ").strip()
        if out:
            args.output = out
        cnt = input("How many messages to convert? [10000, 0 = whole file]: ").strip()
        if cnt:
            args.count = int(cnt)
    args.path = args.path.strip().strip('"').strip("'")
    args.output = args.output or "itch_packets"
    if args.count is None:
        args.count = 10000
    if args.per_packet < 1:
        sys.exit("--per-packet must be at least 1")

    session = args.session.encode("ascii")[:10].ljust(10, b" ")
    midnight = datetime.datetime.strptime(args.date, "%Y-%m-%d").replace(
        tzinfo=datetime.timezone.utc)
    base_epoch = int(midnight.timestamp())

    want_pcap = args.format in ("pcap", "both")
    want_hex = args.format in ("hex", "both")

    n_msgs = n_packets = total_bytes = 0
    seq = args.start_seq

    with open(args.path, "rb") as src:
        if src.read(2) == b"\x1f\x8b":
            sys.exit("still a compressed file")
        src.seek(0)

        pcap = open(args.output + ".pcap", "wb") if want_pcap else None
        hexf = open(args.output + ".hex", "w") if want_hex else None
        try:
            if pcap:
                pcap.write(struct.pack("<IHHiIII", PCAP_NS_MAGIC, 2, 4, 0, 0,
                                       65535, LINKTYPE_ETHERNET))

            batch = []
            batch_size = MOLD_HEADER_LEN

            def flush():
                nonlocal batch, batch_size, seq, n_packets, total_bytes
                if not batch:
                    return
                payload = build_mold_packet(session, seq, batch)
                n_packets += 1
                total_bytes += len(payload)
                if pcap:
                    frame = build_frame(payload, n_packets)
                    ns = itch_timestamp_ns(batch[0])
                    sec = base_epoch + ns // 1_000_000_000
                    nsec = ns % 1_000_000_000
                    pcap.write(struct.pack("<IIII", sec, nsec,
                                           len(frame), len(frame)))
                    pcap.write(frame)
                if hexf:
                    hexf.write(f"// packet {n_packets} seq={seq} "
                               f"count={len(batch)} bytes={len(payload)}\n")
                    for i in range(0, len(payload), 16):
                        hexf.write(payload[i:i + 16].hex(" ").upper() + "\n")
                seq += len(batch)
                batch = []
                batch_size = MOLD_HEADER_LEN

            for msg in read_messages(src, args.skip, args.count):
                n_msgs += 1
                block = 2 + len(msg)
                if batch and (len(batch) >= args.per_packet
                              or batch_size + block > args.max_payload):
                    flush()
                batch.append(msg)
                batch_size += block
            flush()
        finally:
            if pcap:
                pcap.close()
            if hexf:
                hexf.close()

    print(f"Messages read      : {n_msgs}")
    print(f"Packets written    : {n_packets}")
    print(f"MoldUDP64 bytes    : {total_bytes}")
    if n_packets:
        print(f"Sequence range     : {args.start_seq} .. {seq - 1}")
    if want_pcap:
        print(f"Wrote {args.output}.pcap")
    if want_hex:
        print(f"Wrote {args.output}.hex")


main()
