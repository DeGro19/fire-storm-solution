# Operation FIRE STORM – Solution

## Requirements

- Ubuntu 24.04 LTS
- g++ 13 (C++20), CMake ≥ 3.20
- Python 3.12 (to run the challenge's `test.py`)

```bash
sudo apt install -y build-essential cmake python3
```

## Build

```bash
cmake -S . -B build
cmake --build build
```

Debug build with AddressSanitizer and UBSan:

```bash
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug -DFIRE_STORM_SANITIZE=ON
cmake --build build-debug
```

## Run and verify

```bash
./build/fire_storm          # terminal 1
python3 test.py             # terminal 2, from the challenge repo — prints "OK"
```

The reassembled document is written to `output.pdf` in the current directory.
Expected program output:

```
fire_storm: listening on 5733
connection from 127.0.0.1:<port>
valid traffic, forwarding to 5744
done: forwarded 257 frames (32338 bytes), held back 20 CTFS frames
wrote output.pdf from 20 chunks
```

Open `output.pdf` in a PDF reader to confirm the document is intact (3 pages).

## Design

### Protocol analysis

Inspecting the traffic (`python3 test.py --pcap`, then Wireshark) showed that the
stream on port 5733 is a sequence of raw Ethernet frames sent back to back over a
single TCP connection, with no extra framing between them. There are two kinds of frame:

| Frame | Layout | Total length |
|---|---|---|
| Operational (CTFS) | `"CTFS"` · sequence (2 B, big-endian) · length (2 B, big-endian) · 8 unidentified bytes · payload | 16 + length |
| Everything else | Ethernet header (14 B, EtherType `0x0800`) · IPv4 packet | 14 + IPv4 total length |

The CTFS marker occupies the first bytes of the frame (where an Ethernet destination
MAC would normally be), not a TCP/UDP payload. The 16-byte header length was found by
locating `%PDF` in the first CTFS frame. In the capture, sequence numbers 0–19 arrive
slightly out of order (6/7 and 8/9 are swapped), and the final frame carries a zero-length
payload.

### Stream framing

TCP is a byte stream, so one `recv()` may return part of a frame or several frames.
Received bytes are appended to a `pending` buffer and `next_frame()` is called
repeatedly to find complete frames:

- If the buffer starts with `CTFS`, the frame length comes from the CTFS length field.
- Otherwise it must be IPv4, and the length comes from the IPv4 total-length field.
- If not enough bytes are buffered yet, it returns `NeedMore` and the partial frame is
  kept for the next read.
- If neither rule applies (unknown EtherType, impossible IPv4 length), it returns
  `Invalid`. There is no in-band marker to resynchronise on, so mid-stream this is treated
  as fatal rather than guessing and forwarding corrupted data.

All multi-byte fields are decoded with `read_be16()`, which assembles bytes explicitly.
That makes it independent of host byte order and avoids unaligned pointer casts.

### Filtering and forwarding

Non-CTFS frames are forwarded byte-for-byte without modification. CTFS frames are never
forwarded. Forwarded frames from a single read are batched into one buffer and sent with
a single `send_all()`, which loops because `send()` may write only part of the buffer.

### Reassembly

`Reassembler` stores each CTFS payload in a `std::map<uint16_t, std::vector<uint8_t>>`
keyed by sequence number:

- The map keeps keys sorted, so out-of-order arrival needs no extra handling.
- `try_emplace` ignores a sequence number seen before, so a duplicated or retransmitted
  frame can't overwrite or repeat data.
- At end of stream the chunks are written in order to `output.pdf`. Gaps in the sequence
  are reported as warnings, and the partial document is still saved for inspection.

The document is written only after the forward connection is closed, so the downstream
receiver sees EOF as soon as the input ends.

### Robustness to unrelated connections

The listener may receive connections that aren't the FIRE STORM sender, such as a browser
or a port probe. Each accepted connection is handled by `run_session()`:

- Until a valid frame arrives, the connection has a 2-second receive timeout.
- A connection that sends invalid data, sends nothing, or closes early is rejected, and
  the program goes back to listening.
- The forward connection to port 5744 is opened only after the first valid frame. A stray
  connection therefore never reaches the receiver. Connecting retries briefly in case the
  receiver is still starting.
- The listen backlog is 8, so the real sender can queue while a stray connection is
  being rejected.

### Resource management and safety

- Sockets are owned by a move-only RAII `Socket` class, so every exit path closes them.
- `send()` uses `MSG_NOSIGNAL` so a closed peer produces an error instead of killing the
  process with `SIGPIPE`.
- Every length read from the network is checked against the bytes actually buffered
  before use.
- The code builds with `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion`
  without warnings, and passes the test under AddressSanitizer and UBSan.

### Performance

- Reads are 64 KiB and go straight into the end of the `pending` buffer, with no
  intermediate copy.
- Each read results in at most one `send()`, rather than one per frame.
- Consumed bytes are erased from `pending` once per read, not once per frame.
- `pending` and `outbuf` keep their capacity between reads, so after warm-up the
  forwarding path does no new heap allocation. Only the standard library and POSIX
  sockets are used, with no threads.

### Limitations and possible extensions

- One valid stream is handled per run, then the program exits, which matches the test harness.
- Only IPv4 is recognised for non-CTFS frames. IPv6 (`0x86DD`, 40 + payload length) or
  ARP would need additional rules in `next_frame()`.
- The 8 bytes after the CTFS length field are not interpreted. They could be a checksum
  or identifier, but the capture didn't contain enough evidence to tell.
- For higher throughput, `splice()` or `writev()` could forward frames without copying
  them into `outbuf`.

## Use of AI/LLMs

I used Claude (an AI assistant, via Claude Code) throughout this challenge. Specifically:

- Environment setup: Claude guided me through installing WSL2 and Ubuntu 24.04 on Windows and installed the C++ toolchain (g++, CMake, gdb), Python and Wireshark. It also set up the CMake project skeleton.
- Protocol analysis: I generated `output.pcap` and inspected it in Wireshark myself. I opened the capture, found the frames whose destination MAC decoded as `CTFS`, and examined their bytes. Claude explained how to read the hex view and helped me interpret the header: the sequence number, the length field, and the 16-byte header length worked out from where `%PDF` begins.
- Verification: I ran `test.py` on my machine (result: `OK`) and opened the reassembled PDF to confirm it was intact. I have reviewed the code and can explain how each part works.