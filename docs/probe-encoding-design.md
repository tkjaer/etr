# Probe Details Encoding

ETR encodes probe details (TTL and probe number) into packet headers to track which probe generated a response, even when the response is an ICMP error message containing only the first 64 bits of the original packet's transport header.

## Encoding Formula

```
encoded_value = (TTL × 20) + (probe_number % 20)
```

This encoding:
- Supports 20 in-flight probe iterations (0-19) per probe run
- Supports TTL up to 255
- Keeps UDP packets under 1500 byte MTU
- Allows manual decoding (e.g., value 45 = TTL 2, probe iteration 5)

## TCP Encoding

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TCP Header (20+ bytes)                      │
├──────────────────────────────────┬──────────────────────────────────┤
│           Source Port (16)       │       Destination Port (16)      │
├──────────────────────────────────┴──────────────────────────────────┤
│                   Sequence Number (32 bits)                         │
│                                                                     │
│               ┌────────────────────────────────┐                    │
│               │  TTL × 20 + probe_number       │                    │
│               │                                │                    │
│               │  Examples:                     │                    │
│               │    20 = TTL 1,  probe 0        │                    │
│               │    21 = TTL 1,  probe 1        │                    │
│               │    45 = TTL 2,  probe 5        │                    │
│               │  1280 = TTL 64, probe 0        │                    │
│               └────────────────────────────────┘                    │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                   Acknowledgment Number (32)                        │
├──────────┬──────────┬────────────┬──────────────────────────────────┤
│ Offst(4) │ Resvd(4) |  Flags(12) │          Window (16)             │
├──────────┴──────────┴────────────┴──────────────────────────────────┤
│          Checksum (16)           │       Urgent Pointer (16)        │
├──────────────────────────────────┴──────────────────────────────────┤
│                         Options (variable)                          │
└─────────────────────────────────────────────────────────────────────┘

ICMP Error Response includes:
┌─────────────────────────────────────────────────────────────────────┐
│                      ICMP Header (8 bytes)                          │
├─────────────────────────────────────────────────────────────────────┤
│                   IP Header (20+ bytes)                             │
├─────────────────────────────────────────────────────────────────────┤
│              First 64 bits of original TCP header:                  │
│   ┌──────────────────────────────┬──────────────────────────────┐   │
│   │      Source Port (16)        │      Dest Port (16)          │   │
│   ├──────────────────────────────┴──────────────────────────────┤   │
│   │             Sequence Number (32 bits)                       │   │
│   │               (TTL × 20 + probe_number)      ← Encoding here│   │
│   └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Encoding Location:** Sequence Number field (bytes 4-7 of TCP header)
- **Sent Packet:** Full TCP SYN with encoded sequence number
- **ICMP Response:** Contains first 64 bits, including our encoded sequence number
- **Direct Response:** SYN-ACK with Ack = (our Seq + 1), allowing us to decode original value

## UDP Encoding

```
┌─────────────────────────────────────────────────────────────────────┐
│                         UDP Header (8 bytes)                        │
├──────────────────────────────────┬──────────────────────────────────┤
│         Source Port (16)         │     Destination Port (16)        │
├──────────────────────────────────┴──────────────────────────────────┤
│             Length (16)          │         Checksum (16)            │
│                                  │                                  │
│   ┌─────────────────────────┐    │                                  │
│   │ 8 + (TTL × 20 + probe#) │    │                                  │
│   │                         │    │                                  │
│   │ Examples:               │    │                                  │
│   │   28 = TTL 1,  probe 0  │    │                                  │
│   │   29 = TTL 1,  probe 1  │    │                                  │
│   │   53 = TTL 2,  probe 5  │    │                                  │
│   │ 1288 = TTL 64, probe 0  │    │                                  │
│   └─────────────────────────┘    │                                  │
│                                  │                                  │
├──────────────────────────────────┴──────────────────────────────────┤
│                      Payload (variable, filled with zeros)          │
│                   Size = Length - 8 bytes                           │
└─────────────────────────────────────────────────────────────────────┘

ICMP Error Response includes:
┌─────────────────────────────────────────────────────────────────────┐
│                      ICMP Header (8 bytes)                          │
├─────────────────────────────────────────────────────────────────────┤
│                   IP Header (20+ bytes)                             │
├─────────────────────────────────────────────────────────────────────┤
│              First 64 bits of original UDP header:                  │
│   ┌──────────────────────────────┬──────────────────────────────┐   │
│   │      Source Port (16)        │      Dest Port (16)          │   │
│   ├──────────────────────────────┼──────────────────────────────┤   │
│   │        Length (16)           │       Checksum (16)          │   │
│   │     (8 + TTL×20 + #)         │                              │   │
│   │                              │                              │   │
│   │      ↑ Encoding here         │                              │   │
│   └──────────────────────────────┴──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Encoding Location:** Length field (bytes 4-5 of UDP header)
- **Formula:** `length = 8 + (TTL × 20 + probe_number)`
- **Payload Size:** `length - 8` bytes of zeros
- **Constraint:** Max length = 1307 (TTL 64, probe 19 + 8 header) keeps MTU under 1500

## Why This Matters

### RFC 792 ICMP Format Issue

Historic RFC 792 specifies that ICMP error messages should include:
- ICMP header (8 bytes)
- Original IP header (20+ bytes)
- **First 64 bits** of the original transport header

Modern systems often include more, but we're not relying on it.

### The Challenge

With only 64 bits of transport header:
```
Bits 0-15:  Source Port      (needed to match our probe)
Bits 16-31: Destination Port (needed to match our probe)
Bits 32-63: ??? (our encoding goes here)
```

We must encode TTL and probe number in bits 32-63 to identify which probe triggered the ICMP response.

### Protocol-Specific Solutions

**TCP:** Use Sequence Number (bits 32-63)
- Full 32 bits available
- Can encode larger values
- SYN-ACK responses echo Seq+1 in Ack field

**UDP:** Use Length field (bits 32-47, only 16 bits!)
- Limited to 16 bits
- Must stay valid: 8 + payload size
- Must fit in MTU: max ~1500 bytes
- Our encoding: length = 8 + (TTL × 20 + probe)
- Packet is padded with zeros to match the encoded length

## Maximum Constraints

The encoding scheme's constraints are chosen to balance practical network needs with protocol limitations.

**Probe Iteration Count:** 20 iterations (0-19)

The probe number field tracks which iteration of a probe run is currently in-flight, not the number of parallel probes. Here's how it works:

- Each probe run sends packets with TTL 1-30 (or up to max-ttl)
- Multiple iterations of the same run happen sequentially as time passes
- The probe number cycles 0-19, wrapping around every 20 iterations
- With a 1-second timeout, the probe number resets approximately every 20 seconds
- **Parallel probes** (for ECMP path discovery) are differentiated by **source port**, not probe number

20 was chosen as the iteration limit because:
- It provides sufficient temporal resolution to track in-flight probes across multiple timeouts
- It keeps the encoding arithmetic simple and human-readable (multiples of 20)
- It allows the sequence number to fit comfortably in UDP's 16-bit length field even at higher TTLs
- The modulo-20 operation makes manual decoding straightforward (e.g., value 45 = TTL 2, iteration 5)
- With typical 1-second timeouts, cycling every 20 seconds is more than adequate

**TTL Range:** 0-255
- TCP: No practical limit (32-bit sequence number field provides ample space)
- UDP: Limited by MTU
  - Max encoded: 1492 (1500 MTU - 8 byte UDP header)
  - Max TTL: (1492 - 19) / 20 = 73
  - Practical limit with TTL 64: 1288 bytes

The TTL multiplier of 20 was selected because:
- It matches our iteration count, making the encoding formula symmetric and intuitive
- It ensures UDP packets remain valid (length field represents actual packet size)
- It keeps packets well under the standard 1500-byte Ethernet MTU, even at maximum practical TTL
- RFC 1812 recommends a default TTL of 64, and our encoding handles this comfortably with room to spare

**MTU Consideration:**
```
IPv4 Header:  20 bytes (40 with options)
UDP Header:    8 bytes
UDP Payload: 1280 bytes (for TTL 64, probe 0)
────────────────────────
Total:       1308 bytes (well under 1500)
```

This design ensures compatibility across diverse network environments while providing sufficient temporal resolution for tracking in-flight probes. The actual number of ECMP paths that can be discovered is determined by the number of parallel probes (configured via the `-P` flag), which use different source ports to trigger different ECMP hash calculations.
