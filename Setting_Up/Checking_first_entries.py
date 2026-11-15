import argparse
import struct
import sys
from collections import Counter

TYPE_NAMES = {
    "S": "System Event",
    "R": "Stock Directory",
    "H": "Stock Trading Action",
    "Y": "Reg SHO Restriction",
    "L": "Market Participant Position",
    "V": "MWCB Decline Level",
    "W": "MWCB Status",
    "K": "IPO Quoting Period Update",
    "J": "LULD Auction Collar",
    "h": "Operational Halt",
    "A": "Add Order",
    "F": "Add Order (MPID)",
    "E": "Order Executed",
    "C": "Order Executed w/ Price",
    "X": "Order Cancel",
    "D": "Order Delete",
    "U": "Order Replace",
    "P": "Trade (non-cross)",
    "Q": "Cross Trade",
    "B": "Broken Trade",
    "I": "NOII",
    "N": "Retail Price Improvement",
}

# Expected total message length (type byte included, 2-byte prefix excluded).
EXPECTED_LEN = {
    "S": 12, "R": 39, "H": 25, "Y": 20, "L": 26, "V": 35, "W": 12, "K": 28,
    "J": 35, "h": 21, "A": 36, "F": 40, "E": 31, "C": 36, "X": 23, "D": 19,
    "U": 35, "P": 44, "Q": 40, "B": 19, "I": 50, "N": 20,
}

EVENT_CODES = {
    "O": "Start of messages", "S": "Start of system hours",
    "Q": "Start of market hours", "M": "End of market hours",
    "E": "End of system hours", "C": "End of messages",
}


def u16(b, o): return struct.unpack_from(">H", b, o)[0]
def u32(b, o): return struct.unpack_from(">I", b, o)[0]
def u64(b, o): return struct.unpack_from(">Q", b, o)[0]
def txt(b, o, n): return b[o:o + n].decode("ascii", "replace").rstrip()
def ch(b, o): return chr(b[o])
def price(b, o): return f"{u32(b, o) / 10000:.4f}"


def timestamp(b, o=5):
    ns = int.from_bytes(b[o:o + 6], "big")  # nanoseconds since midnight
    s, n = divmod(ns, 1_000_000_000)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}.{n:09d}"


def decode(msg):
    """Return a one-line description of a message (bytes, type byte first)."""
    t = chr(msg[0])
    if t not in EXPECTED_LEN:
        return f"{msg[:24].hex(' ')}{' ...' if len(msg) > 24 else ''}"

    head = f"locate={u16(msg, 1):<5} ts={timestamp(msg)}"
    try:
        if t == "S":
            code = ch(msg, 11)
            return f"{head} event={code} ({EVENT_CODES.get(code, '?')})"
        if t == "R":
            return (f"{head} stock={txt(msg, 11, 8):<8} category={ch(msg, 19)} "
                    f"status={ch(msg, 20)} round_lot={u32(msg, 21)} "
                    f"etp={ch(msg, 33)}")
        if t == "H":
            return (f"{head} stock={txt(msg, 11, 8):<8} state={ch(msg, 19)} "
                    f"reason={txt(msg, 21, 4)!r}")
        if t == "Y":
            return f"{head} stock={txt(msg, 11, 8):<8} reg_sho_action={ch(msg, 19)}"
        if t in ("A", "F"):
            extra = f" mpid={txt(msg, 36, 4)}" if t == "F" else ""
            return (f"{head} ref={u64(msg, 11)} side={ch(msg, 19)} "
                    f"shares={u32(msg, 20)} stock={txt(msg, 24, 8):<8} "
                    f"price={price(msg, 32)}{extra}")
        if t == "E":
            return (f"{head} ref={u64(msg, 11)} shares={u32(msg, 19)} "
                    f"match={u64(msg, 23)}")
        if t == "C":
            return (f"{head} ref={u64(msg, 11)} shares={u32(msg, 19)} "
                    f"match={u64(msg, 23)} printable={ch(msg, 31)} "
                    f"price={price(msg, 32)}")
        if t == "X":
            return f"{head} ref={u64(msg, 11)} cancelled_shares={u32(msg, 19)}"
        if t == "D":
            return f"{head} ref={u64(msg, 11)}"
        if t == "U":
            return (f"{head} orig_ref={u64(msg, 11)} new_ref={u64(msg, 19)} "
                    f"shares={u32(msg, 27)} price={price(msg, 31)}")
        if t == "P":
            return (f"{head} ref={u64(msg, 11)} side={ch(msg, 19)} "
                    f"shares={u32(msg, 20)} stock={txt(msg, 24, 8):<8} "
                    f"price={price(msg, 32)} match={u64(msg, 36)}")
        if t == "Q":
            return (f"{head} shares={u64(msg, 11)} stock={txt(msg, 19, 8):<8} "
                    f"cross_price={price(msg, 27)} match={u64(msg, 31)} "
                    f"cross_type={ch(msg, 39)}")
    except struct.error:
        return f"{head} (truncated message)"
    return f"{head} {msg[11:].hex(' ')}"



ap = argparse.ArgumentParser(description="Dump ITCH 5.0 messages as text")
ap.add_argument("path", nargs="?", default=None,
                    help="decompressed ITCH 5.0 file (prompted for if omitted)")
ap.add_argument("-n", "--count", type=int, default=100000000,
                    help="number of messages to print (default 100)")
ap.add_argument("--skip", type=int, default=0,
                    help="messages to skip before printing (default 0)")
ap.add_argument("--hex", action="store_true",
                    help="also print the raw bytes (length prefix included)")
args = ap.parse_args()

    # No path on the command line (e.g. pressing Run in PyCharm): ask for it.
if not args.path:
    args.path = input("Enter the full path to the decompressed ITCH file: ")
    # Tidy up pasted paths (surrounding quotes/spaces, e.g. "Copy as path").
args.path = args.path.strip().strip('"').strip("'")

counts = Counter()
printed = 0
index = 0

with open(args.path, "rb") as f:
        # Quick sanity check: a gzip file starts with 1f 8b.
    if f.read(2) == b"\x1f\x8b":
        sys.exit("This looks like the still-compressed .gz file. "
                     "Decompress it first (gunzip / 7-Zip).")
    f.seek(0)

    while printed < args.count:
        prefix = f.read(2)
        if len(prefix) < 2:
            print("-- end of file --")
            break
        length = struct.unpack(">H", prefix)[0]
        msg = f.read(length)
        if len(msg) < length or length == 0:
            print(f"-- bad or truncated message at index {index} "
                    f"(length={length}) - wrong file or framing? --")
            break

        index += 1
        if index <= args.skip:
            continue

        t = chr(msg[0])
        counts[t] += 1
        printed += 1

        warn = ""
        if t in EXPECTED_LEN and EXPECTED_LEN[t] != length:
            warn = f"  [!] length {length}, expected {EXPECTED_LEN[t]}"

        print(f"{index:>5}  {t} {TYPE_NAMES.get(t, 'Unknown'):<28} "
                f"len={length:<3} {decode(msg)}{warn}")
        if args.hex:
            print(f"       raw: {(prefix + msg).hex(' ')}")

print("\nMessage types in this sample:")
for t, c in counts.most_common():
    print(f"  {t}  {TYPE_NAMES.get(t, 'Unknown'):<28} {c}")

