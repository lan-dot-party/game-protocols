# TrackMania Original / Sunrise / Nations ESWC – Server Query Network Protocol

> **Purpose of this document:** A complete, verified reference on how to discover and query a server of the
> classic TrackMania games (TrackMania Original, TrackMania Sunrise / Sunrise eXtreme and TrackMania Nations
> ESWC) using the game's own protocol, and how to decode the response.
> Written so that a developer or an LLM can rebuild the protocol 1:1 without access to the binary.
>
> - **Source:** Reverse engineering of `TrackManiaServer.exe` of TrackMania Sunrise eXtreme (x86, image base
>   `0x00400000`) with Ghidra. All statements are derived from the decompiled code, not from existing implementations.
> - **Verified:** live against a TrackMania Sunrise eXtreme dedicated server on Windows (see [Section 14](#14-verification-status)).
> - **As of:** 2026-10-05.
> - **Related:** [Trackmania-Nations.md](Trackmania-Nations.md) describes the successor protocol of TrackMania
>   Forever (TMNF/TMUF). Both protocols share framing, compression and the query flow, but differ in key details
>   (see [Section 13](#13-differences-to-trackmania-forever)). A TmForever query gets **no** answer from a Sunrise
>   server (verified live); a Sunrise query is discarded by a TmForever server (derived: it requires its own checksum).

---

## Contents

0. [Summary](#0-summary)
1. [Context, games and ports](#1-context-games-and-ports)
2. [Data types and encodings](#2-data-types-and-encodings)
3. [TCP framing and message header](#3-tcp-framing-and-message-header)
4. [Checksum (HMAC-MD5)](#4-checksum-hmac-md5)
5. [Compression (LZO1X)](#5-compression-lzo1x)
6. [Message types](#6-message-types)
7. [CNetFormConnectionAdmin and the query flow](#7-cnetformconnectionadmin-and-the-query-flow)
8. [The server info (response payload)](#8-the-server-info-response-payload)
9. [UDP LAN discovery](#9-udp-lan-discovery)
10. [Annotated examples (real capture)](#10-annotated-examples-real-capture)
11. [Robust detection of a server](#11-robust-detection-of-a-server)
12. [Reference implementation (Python, standard library only)](#12-reference-implementation-python-standard-library-only)
13. [Differences to TrackMania Forever](#13-differences-to-trackmania-forever)
14. [Verification status](#14-verification-status)
15. [Ghidra index (addresses, class IDs)](#15-ghidra-index-addresses-class-ids)
16. [Existing implementations](#16-existing-implementations)

---

## 0. Summary

```
Discovery (UDP, broadcast or unicast to the game port 2350), one datagram per game id:

  82 00 [u32 checksum] [str game_id] [str client] [6 bytes 0] [u32 nonce]        CNetFormQuerrySessions
  game_id = "TmOriginal" | "TmSunrise" | "TmNationsESWC"; only a server running that game answers:
  82 01 [u32 checksum] [u32 nonce] [str "GameNet"] [str game_id] [str version] [str host] [addr] [addr]

Query (TCP to the game port), both messages in one write:

  [u32 len=14] 82 03 [u32 checksum] 04000000 08000000                ConnectionAdmin v4, subtype 8 (query mode)
  [u32 len=18] 82 03 [u32 checksum] 04000000 07000000 [u32 id]       ConnectionAdmin v4, subtype 7 (info request)

  version = 4 for Original and Sunrise, 5 for Nations ESWC (must match exactly)

Read response frames until type 3 / subtype 6 / request_id == id:

  [u32 len] 83 03 [u32 checksum] [u32 size] LZO1X data  →  04000000 06000000 [u32 id] [u32 n] [n bytes server info]

checksum:  w = HMAC-MD5(KEY, message with zeroed checksum field) as four u32;  w[0] + w[1] + w[2] + key[0]
KEY:       08 c4 81 30 3a 12 26 ab af 1d 6a e4 fb 65 fb c9            (key[0] = 0x3081C408)

Server info: u8 0x07|0x09 | IP (4 bytes, reversed) | u16 port | str host login | str "#SRV#"+{"",p,s,f}
             | wstr "" | u8 players, max players, spectators, max spectators, ladder mode | wstr server name
             | u32 n, n × wstr player name, n × i32 ladder ranking | wstr comment | u8 mode | u32 limit
             | u8 #maps | u32 m, m × (wstr name, u32 decoration index, u32 gold time, u32 copper price)
str = wstr = u32 length + UTF-8 (wstr with BOM EF BB BF if non-ASCII)
```

All integers are **little-endian**.

---

## 1. Context, games and ports

One dedicated server binary serves three games. The game is selected with the command line option `/game=`
(`0x00401d60`):

| `/game=` | Game | Game id (LAN discovery) | ConnectionAdmin version | Game tag (server info) |
|---|---|---|---|---|
| `Original` | TrackMania Original | `TmOriginal` | 4 | `0x07` |
| `Sunrise` | TrackMania Sunrise / Sunrise eXtreme | `TmSunrise` | 4 | `0x07` |
| `Nations` | TrackMania Nations ESWC | `TmNationsESWC` | 5 | `0x09` |

Original and Sunrise use the same version and game tag. **They can only be told apart via the LAN discovery**
([Section 9](#9-udp-lan-discovery)), because a server only answers the discovery query for its own game id.

TrackMania Nations ESWC (2006) is the predecessor of TrackMania Nations Forever; TMNF uses the newer protocol in
[Trackmania-Nations.md](Trackmania-Nations.md).

| Port | Protocol | Purpose |
|---|---|---|
| **2350/TCP** (`server_port`) | Nadeo network protocol (this document) | Game connection **and** server query |
| **2350/UDP** | Nadeo network protocol | In-game UDP and **LAN discovery** ([Section 9](#9-udp-lan-discovery)) |
| 3450 (`server_p2p_port`) | P2P file transfer | not covered by this document |
| 5000/TCP (`xmlrpc_port`) | GbxRemote (XML-RPC) | Remote administration, requires credentials, local only by default |

The query requires **no credentials**.

---

## 2. Data types and encodings

| Type | Encoding | Archive function (Ghidra) |
|---|---|---|
| `u8` | 1 byte | `0x00418cc0` |
| `u32` / `i32` | 4 bytes LE | `0x00418d00` |
| `str` | `u32` byte length + bytes, no null terminator. ASCII in practice; decode as UTF-8. | `0x00418da0` |
| `wstr` | UTF-16 internally, **UTF-8** on the wire: `u32` byte length + bytes. If the text contains non-ASCII characters, it is preceded by a **UTF-8 BOM `EF BB BF`** (included in the length). Decode with `utf-8-sig`. | `0x00418dc0`, conversion `0x004152f0`, BOM at `0x00844698` |
| `addr` | 4 bytes IPv4 in **reversed** order, followed by `u16` port (LE) | `0x004979e0` |

**IPv4 example:** the bytes `04 65 0a 0a` yield `10.10.101.4`, the port `2e 09` yields 2350.

**TrackMania format codes:** names and comments may contain formatting. Strip them with
`\$(\$|[0-9a-fA-F]{1,3}|[lLhHpP]\[[^\]]*\]|.)`: `$$` becomes `$`, everything else becomes an empty string.

---

## 3. TCP framing and message header

Identical to TrackMania Forever. Every message on TCP:

```
u32  length            length of the following message (excluding these 4 bytes)
u8   flags             upper nibble MUST be 0x8
u8   type              message type (index into the type table, Section 6)
[u16 sequence]         only if flags & 0x0C
[u32 checksum]         only if flags & 0x02
payload                if flags & 0x01: u32 uncompressed size + LZO1X stream
                       otherwise: payload uncompressed
```

| Flag bit | Meaning |
|---|---|
| `0x80` | Mandatory marker (`(flags & 0xF0) == 0x80`) |
| `0x01` | Payload is LZO1X-compressed |
| `0x02` | Checksum present |
| `0x04` / `0x08` | Sequence number (reliable delivery) |

- **Receive logic** (`0x004afc70`, `CNetConnection::TcpReceive`): read 4 bytes of length, then exactly that many bytes.
- **Decoding** (`0x004a9730`): check flags, look up the type in the table, check sequence number and checksum,
  decompress, then call the type-specific decoder and instantiate the class.
- **UDP datagrams** carry the same message **without** the `u32` length prefix.
- **Messages sent by the client:** `flags = 0x82` (checksum, uncompressed, no sequence).
- **Messages received from the server:** `0x82` or `0x83` (compressed). The server always sets the checksum.

The decoder also contains a legacy format (selected per connection, `+0x3c == 1`) with a `u32` header whose high
word is 1; the game server does not use it.

---

## 4. Checksum (HMAC-MD5)

The HMAC construction (`0x00419310`, MD5 `0x00419770`/`0x004197a0`/`0x0041a1b0`) is the same as in TrackMania
Forever, but the **key** and the **reduction to 32 bits** differ:

```python
KEY = bytes.fromhex("08c481303a1226abaf1d6ae4fb65fbc9")      # 0x00854f74, 16 bytes

def checksum(message: bytes, pos: int) -> int:                # message = from the flags byte, without length prefix
    data = bytearray(message)
    data[pos:pos + 4] = b"\0\0\0\0"                             # the checksum field counts as 0
    w = struct.unpack("<4I", hmac.new(KEY, bytes(data), hashlib.md5).digest())
    return (w[0] + w[1] + w[2] + struct.unpack_from("<I", KEY)[0]) & 0xFFFFFFFF
```

- The sum uses the **first three digest words plus the first key word** (`0x3081C408`), not the fourth digest
  word. This is how the server computes it (decoder at `0x004a9972`: the fourth addend is read from the key slot of
  the HMAC context). Verified live: requests with the TmForever-style sum of four digest words are silently dropped,
  requests with this formula are answered, and every server reply matches it.
- `pos` is 2 (without sequence number) or 4 (with sequence number). The checksum covers the entire message
  (for compressed messages the compressed content).
- **For the message types used here the checksum is optional:** types 0, 1 and 3 have a type-specific decoder, and
  the generic decoder only requires the checksum for types without one. A request with `flags = 0x80` and no checksum
  is answered as well (verified live). Clients should still send it and must verify it on replies, as it is the
  strongest indicator of a TrackMania server.

---

## 5. Compression (LZO1X)

Identical to TrackMania Forever: if `flags & 0x01`, a `u32 uncompressed_size` follows, then an **LZO1X-1** stream.
The server uses `lzo1x_decompress_safe` (`0x006f10e0`). A decompressor is part of the reference implementation in
[Section 12](#12-reference-implementation-python-standard-library-only), the LZO1X quick reference is in
[Trackmania-Nations.md, Section 5](Trackmania-Nations.md#5-compression-lzo1x).

The info reply is compressed, so its text fragments are visible in a capture, but the structure cannot be parsed
without decompression.

---

## 6. Message types

Type table at `0x007f2130`, entries of 8 DWORDs each:
`[class ID, type byte, ?, sequence flags, sequence window, ?, type-specific decoder, factory]`.

| Type | Class | Class ID | Decoder | Meaning |
|---|---|---|---|---|
| **0** | **`CNetFormQuerrySessions`** | `0x12007000` | `0x004b1260` | **LAN discovery: request (UDP)** |
| **1** | **`CNetFormEnumSessions`** | `0x12008000` | `0x004b1460` | **LAN discovery: response (UDP)** |
| 2 | `CNetFormPing` | `0x12009000` | `0x004b1640` | not analyzed |
| **3** | **`CNetFormConnectionAdmin`** | **`0x12010000`** | **`0x004b2070`** | **Connection management incl. server query** |
| 4 | (unnamed) | `0x1201b000` | `0x004b0ba0` | not analyzed |
| 5… | Game forms (`0x0300A000`, …) | – | – | Game traffic, irrelevant for the query |

The type is an **index into this table**, not a class ID.

---

## 7. CNetFormConnectionAdmin and the query flow

### 7.1 Payload

```
u32 version     4 for Original and Sunrise, 5 for Nations ESWC (0x004b1cd0)
u32 subtype     0..10
...             depends on subtype
```

Archive function `0x004b1dd0`, decoder `0x004b2070`. The decoder only accepts `version <= own version`,
`subtype < 11`, and checks the payload size per subtype:

| Subtype | Direction | Content | Payload size | Meaning |
|---|---|---|---|---|
| 0 | C→S | Object | – | Connection request (game join) |
| 1 | S→C | `u32`, `str` message, `u32` | – | **Rejection**, e.g. `"Please upgrade your application."` |
| 2 / 3 | both | `u32` | 12 | Handshake steps |
| 4 | both | `u32` | 12 | UDP status |
| 5 | C→S | `u32 request_id` | – | like 7, but **without a response** |
| **6** | **S→C** | **`u32 request_id`, `u32 size`, `u8[size]`** | – | **Info response** |
| **7** | **C→S** | **`u32 request_id`** | **exactly 12** | **Info request** |
| **8** | **C→S** | – | **exactly 8** | **Put the connection into query mode** |
| 9 / 10 | – | – | – | Game handshake, irrelevant for the query |

### 7.2 Flow

```
Client                                                Server
  │ TCP connect :2350                                    │
  │── ConnectionAdmin v4 subtype 8 ──────────────────────▶│  handled immediately (0x004b86d0): state → 0x40
  │── ConnectionAdmin v4 subtype 7, request_id ─────────▶│
  │◀── ConnectionAdmin v4 subtype 6, request_id, info ───│  0x0074d940, info = CTrackManiaNetworkServerInfo
  │ close                                                │
```

- **Subtype 8 is mandatory**, both messages may be sent in a single TCP write.
- **`request_id`** can be chosen freely (≠ `0xFFFFFFFF`); the server echoes it.
- The response arrives within a few milliseconds (LAN: ~8–12 ms measured). Read frames in a loop and skip others.

### 7.3 Version handling and error cases

The handler `0x004b86d0` requires the version to be **exactly** the server's version:

| Situation | Server behavior (verified live where marked ✅) |
|---|---|
| version == server version (4 for Original/Sunrise) | Answer as above ✅ |
| version < server version (e.g. 3 to a Sunrise server) | Subtype 1 reply with the **server's version** in the header and the message `"Please upgrade your application."`, then disconnect ✅ |
| version > server version (e.g. 5 or 7 to a Sunrise server) | Message discarded by the decoder, no answer ✅ |
| Server has no game info yet | Subtype 6 with `request_id = 0xFFFFFFFF` and empty data (`0x0074d940`) |
| wrong checksum | Message discarded, no answer ✅ |

**Recommended strategy:** send version 4. A Nations ESWC server refuses it with a subtype 1 reply carrying version 5;
repeat the query with version 5. (Sending 5 first would make Original/Sunrise servers silently ignore the request.)

Refusal as received from a Sunrise server for a version 3 request (uncompressed payload):

```
04000000 01000000 00000000 20000000 "Please upgrade your application." 00000000
version 4  subtype 1  u32 0      str length 32                               u32 0
```

---

## 8. The server info (response payload)

### 8.1 Serialization chain

Each class writes the fields of its base class first (archive method at vtable `+0x88`):

```
CNetMasterHost                   0x004c8870   game tag, address, host login
└ CGameNetServerInfo             0x0074cb80   player login "#SRV#…"
  └ (game server info)           0x006ac250   unused string, counters, name (0x006ac480), players, comment
    └ CTrackManiaNetworkServerInfo 0x0069a940 game mode, limit, challenge window
```

Compared to TrackMania Forever there is **no pack mask** and **no environment list**, and the challenge entries
have a different layout.

### 8.2 Field table

| # | Type | Field | Condition / remark |
|---|---|---|---|
| 1 | `u8` | **Game tag** | `(tag & 0xE0) == 0` → valid (`0x004c87b0`); `(tag & 0x1F)` is `0x07` for Original/Sunrise, `0x09` for Nations ESWC (`0x0069acb0`) |
| 2 | `addr` | Server address and port | the IP under which the server reports itself |
| 3 | `str` | **Host login** | In LAN mode the **computer name**. **Not** the server name! |
| 4 | `str` | **Server's player login** | `"#SRV#"` plus password flag, see 8.3 |
| | | *From here on only if the tag is valid and the login starts with `#SRV#`.* | |
| 5 | `wstr` | unused | always empty (`u32 0`) |
| 6 | `u8` | PlayerCount | current players |
| 7 | `u8` | MaxPlayerCount | player slots |
| 8 | `u8` | SpectatorCount | current spectators |
| 9 | `u8` | MaxSpectatorCount | spectator slots |
| 10 | `u8` | LadderMode | 0 = inactive |
| 11 | `wstr` | **ServerName** | incl. format codes |
| 12 | `u32 n` | Number of players | |
| 13 | `n × wstr` | Player nicknames | incl. format codes |
| 14 | `n × i32` | Ladder ranking per player | |
| 15 | `wstr` | Comment | Server comment |
| | | *From here on the TrackMania part (only with full info, always the case for the query)* | |
| 16 | `u8` | **GameMode** (internal ID) | see 8.4 |
| 17 | `u32` | **Mode limit** | meaning depends on the mode, see 8.4 (`0x0069a8a0`) |
| 18 | `u8` | NbChallenges | number of maps in the playlist, capped at 255 |
| 19 | `u32 m` | Number of maps in the packet | `min(NbChallenges, 20)` |
| 20 | `m ×` | Map entry | `wstr name`, `u32 DecorationIndex`, `u32 GoldTime (ms)`, `u32 CopperPrice` (`0x0069ad50`), see 8.5 |

The payload ends exactly after field 20 (checked byte-for-byte against the live capture).

As in TrackMania Forever, PlayerCount and MaxPlayerCount are decreased by 1 when writing if the server is hosted
in-game (`0x006ac480`, flag `+0x1c`).

### 8.3 Password flags in the `#SRV#` login

Generated in `0x0074cd90` from the flags "player password set" (`+0x50`) and "spectator password set" (`+0x58`).
The XML-RPC methods confirm the mapping: `SetServerPassword` (`0x00626320` → `0x006268b0`) writes `+0x50`,
`SetServerPasswordForSpectator` (`0x00626470` → `0x006269a0`) writes `+0x58`.

| Login | Player password | Spectator password |
|---|---|---|
| `#SRV#` | no | no |
| `#SRV#p` | **yes** | no |
| `#SRV#s` | no | **yes** |
| `#SRV#f` | **yes** | **yes** |

Strings at `0x008b954c` (`#SRV#`), `0x008b9544` (`#SRV#p`), `0x008b953c` (`#SRV#s`), `0x008b9534` (`#SRV#f`).

### 8.4 Game modes and limit

The internal mode ID differs from the XML-RPC numbering (mapping `0x0069ae00`):

| Internal | Mode | XML-RPC `GameMode` | Field 17 means |
|---|---|---|---|
| 1 | TimeAttack | 1 | Time limit in ms (`+0x1cc`) |
| 3 | Rounds | 0 | Points limit (`+0x1c4`) |
| 6 | Team | 2 | Points limit (`+0x1c4`) |
| 7 | Laps | 3 | Number of laps (`+0x1c0`) |
| 8 | Stunts | 4 | Time limit in ms (`+0x1cc`) |
| other | unknown | – | 0 |

The mapping table also knows internal ID 9 (XML-RPC 5, Cup in TmForever), but `SetGameMode` rejects modes above 4.
Verified live: TimeAttack with 300000 ms.

### 8.5 Maps (challenges)

- Starting at the **current** playlist index, `min(count, 20)` entries are written, wrapping at the end of the list
  (`0x0069a940`). **The first entry is the current map**, followed by the next ones in rotation order.
  Live: 54 maps on the server, 20 in the packet.
- **Names are truncated to 15 characters** (UTF-16 units, before UTF-8 encoding).
- **GoldTime** is the gold medal time in ms, **CopperPrice** the coppers display price
  (the client shows it as `"%d C"`, `0x005e3280`).
- **DecorationIndex** is the challenge parameter `CollectionId2` (class `0x2400B000`, offset `+0x74`). The server
  computes it as **2 + index of the challenge's decoration (environment + mood ident) in a decoration table** that is
  built at runtime from the game data (`0x005e2af0` → `0x005eb450`), 0 if not found. It is engine internal and cannot
  be mapped to an environment name reliably. Live values were 2–15 and stable per map
  (e.g. `NightFlight` 13, `CarPark` 12, `HappyBay` 2). The environment itself is **not** part of the packet; the
  full challenge list incl. environment and mood is only available via XML-RPC (`GetChallengeList`).

---

## 9. UDP LAN discovery

> ✅ **Fully analyzed and verified live**, including broadcast.

The game client finds LAN servers by sending `CNetFormQuerrySessions` to the server port; the server
(`0x004b81d0`) compares the game id of the query with its own and only then answers with `CNetFormEnumSessions` to
the **sender's address and port**. This both finds servers and identifies the game.

**Query** (`CNetFormQuerrySessions`, type 0, archive `0x004b11e0`, decoder `0x004b1260`):

```
str  game_id     "TmOriginal", "TmSunrise" or "TmNationsESWC" (length ≤ 255); compared with the server's game id
str  client      free text (length ≤ 255), not checked
addr address     6 bytes, not used by the server (send zeros)
u32  nonce       echoed in the response
```

The decoder requires the payload size to be exactly `4 + len(game_id) + 4 + len(client) + 10`.

**Response** (`CNetFormEnumSessions`, type 1, archive `0x004b1430`, decoder `0x004b1460`):

```
u32  nonce             echo of the query
CNetServerInfo         (archive 0x004aa410)
  str  application     "GameNet"
  str  game_id         e.g. "TmSunrise"
  str  version         network version string, "1.043" on the tested server
  str  host_name       computer name of the server
  addr address 1       server address and game port
  addr address 2       second announced address (identical on the tested server)
```

**Practical use:**

- Send one query per game id in a single burst; each server answers exactly one of them.
- Broadcast to `255.255.255.255:2350` and/or the subnet broadcast address; servers on non-default ports listen on
  their own port, so also send to 2351, 2352, … if needed.
- The answer arrives within milliseconds; a collection window of 1–2 s is plenty.
- Then query each answering server via TCP ([Section 7](#7-cnetformconnectionadmin-and-the-query-flow)) for the
  details. The discovery reply contains no player counts or map.

---

## 10. Annotated examples (real capture)

Live traffic with a TrackMania Sunrise eXtreme dedicated server "Sunrise LAN Server" (10.10.101.4, Windows),
TimeAttack, 54 maps. The tables were generated by script from the real bytes.

### Request 1: ConnectionAdmin subtype 8

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `0e 00 00 00` | TCP frame length | 14 |
| 0x04 | `82` | flags | 0x82 (0x80 + 0x02 checksum) |
| 0x05 | `03` | Message type | 3 = CNetFormConnectionAdmin |
| 0x06 | `8b 94 33 74` | Checksum | 0x7433948b |
| 0x0a | `04 00 00 00` | version | 4 |
| 0x0e | `08 00 00 00` | subtype | 8 |

### Request 2: ConnectionAdmin subtype 7 (request_id 0x00001234)

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `12 00 00 00` | TCP frame length | 18 |
| 0x04 | `82` | flags | 0x82 (0x80 + 0x02 checksum) |
| 0x05 | `03` | Message type | 3 = CNetFormConnectionAdmin |
| 0x06 | `46 e5 b8 53` | Checksum | 0x53b8e546 |
| 0x0a | `04 00 00 00` | version | 4 |
| 0x0e | `07 00 00 00` | subtype | 7 |
| 0x12 | `34 12 00 00` | request_id | 0x00001234 |

### Response: outer frame

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `33 02 00 00` | TCP frame length | 563 |
| 0x04 | `83` | flags | 0x83 (0x80 + 0x02 checksum + 0x01 LZO) |
| 0x05 | `03` | Message type | 3 = CNetFormConnectionAdmin |
| 0x06 | `ad f7 3b 18` | Checksum | 0x183bf7ad |
| 0x0a | `77 02 00 00` | Uncompressed size | 631 |
| 0x0e | `00 06 04 00 00 00 06 00 …` | LZO1X stream | 553 bytes |

### Response: unpacked ConnectionAdmin payload

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `04 00 00 00` | version | 4 |
| 0x04 | `06 00 00 00` | subtype | 6 = info response |
| 0x08 | `34 12 00 00` | request_id (echo) | 0x00001234 |
| 0x0c | `67 02 00 00` | Server info length | 615 |

### Server info

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `07` | Game tag | 0x07 → (v & 0xE0) = 0 valid, (v & 0x1F) = 0x07 Original/Sunrise |
| 0x01 | `04 65 0a 0a` | IPv4 (reversed byte order) | 10.10.101.4 |
| 0x05 | `2e 09` | Port | 2350 |
| 0x07 | `0f 00 00 00` | Host login (LAN: computer name) (length) | 15 |
| 0x0b | `44 45 53 4b 54 4f 50 2d 4a 42 4b 4c 35 4a 30` | Host login (LAN: computer name) | 'DESKTOP-JBKL5J0' |
| 0x1a | `05 00 00 00` | Server player login + password flag (length) | 5 |
| 0x1e | `23 53 52 56 23` | Server player login + password flag | '#SRV#' |
| 0x23 | `00 00 00 00` | Unused wstr (always empty) (length) | 0 |
| 0x27 | `00` | PlayerCount | 0 |
| 0x28 | `20` | MaxPlayerCount | 32 |
| 0x29 | `00` | SpectatorCount | 0 |
| 0x2a | `20` | MaxSpectatorCount | 32 |
| 0x2b | `00` | LadderMode | 0 |
| 0x2c | `12 00 00 00` | ServerName (wstr) (length) | 18 |
| 0x30 | `53 75 6e 72 69 73 65 20 4c 41 4e 20 53 65 72 76 65 72` | ServerName (wstr) | 'Sunrise LAN Server' |
| 0x42 | `00 00 00 00` | Number of players | 0 |
| 0x46 | `1e 00 00 00` | Comment (wstr) (length) | 30 |
| 0x4a | `54 72 61 63 6b 4d 61 6e 69 61 20 53 75 6e 72 69 73 65 20 45 78 74 72 65 6d 65 20 4c 41 4e` | Comment (wstr) | 'TrackMania Sunrise Extreme LAN' |
| 0x68 | `01` | GameMode | 1 = TimeAttack |
| 0x69 | `e0 93 04 00` | Mode limit | 300000 ms = 5:00 min |
| 0x6d | `36` | NbChallenges (playlist, max 255) | 54 |
| 0x6e | `14 00 00 00` | Number of challenges in the packet | 20 |
| 0x72 | `0b 00 00 00` | Challenge[0].Name (wstr, ≤15 characters) (length) | 11 |
| 0x76 | `4e 69 67 68 74 46 6c 69 67 68 74` | Challenge[0].Name (wstr, ≤15 characters) | 'NightFlight' |
| 0x81 | `0d 00 00 00` | Challenge[0].DecorationIndex | 13 |
| 0x85 | `ee 98 00 00` | Challenge[0].GoldTime (ms) | 39150 |
| 0x89 | `ab 05 00 00` | Challenge[0].CopperPrice | 1451 |
| 0x8d | `07 00 00 00` | Challenge[1].Name (wstr, ≤15 characters) (length) | 7 |
| 0x91 | `43 61 72 50 61 72 6b` | Challenge[1].Name (wstr, ≤15 characters) | 'CarPark' |
| 0x98 | `0c 00 00 00` | Challenge[1].DecorationIndex | 12 |
| 0x9c | `f6 90 00 00` | Challenge[1].GoldTime (ms) | 37110 |
| 0xa0 | `d1 04 00 00` | Challenge[1].CopperPrice | 1233 |
| … | | 18 more challenges | payload ends after the last one (0x267 bytes) |

### UDP session query (TmSunrise, nonce 0x00C0FFEE)

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `82` | flags | 0x82 |
| 0x01 | `00` | Message type | 0 = CNetFormQuerrySessions |
| 0x02 | `35 8e a5 ef` | Checksum | 0xefa58e35 |
| 0x06 | `09 00 00 00` | Game id (length) | 9 |
| 0x0a | `54 6d 53 75 6e 72 69 73 65` | Game id | 'TmSunrise' |
| 0x13 | `01 00 00 00` | Client name (free) (length) | 1 |
| 0x17 | `78` | Client name (free) | 'x' |
| 0x18 | `00 00 00 00 00 00` | Address (not used by the server) | 0.0.0.0:0 |
| 0x1e | `ee ff c0 00` | Nonce | 0x00c0ffee |

### UDP session reply

| Offset | Bytes | Field | Value |
|---:|---|---|---|
| 0x00 | `82` | flags | 0x82 |
| 0x01 | `01` | Message type | 1 = CNetFormEnumSessions |
| 0x02 | `86 ed 3e 6e` | Checksum | 0x6e3eed86 |
| 0x06 | `ee ff c0 00` | Nonce (echo) | 0x00c0ffee |
| 0x0a | `07 00 00 00` | Application (length) | 7 |
| 0x0e | `47 61 6d 65 4e 65 74` | Application | 'GameNet' |
| 0x15 | `09 00 00 00` | Game id (length) | 9 |
| 0x19 | `54 6d 53 75 6e 72 69 73 65` | Game id | 'TmSunrise' |
| 0x22 | `05 00 00 00` | Version (length) | 5 |
| 0x26 | `31 2e 30 34 33` | Version | '1.043' |
| 0x2b | `0f 00 00 00` | Host name (length) | 15 |
| 0x2f | `44 45 53 4b 54 4f 50 2d 4a 42 4b 4c 35 4a 30` | Host name | 'DESKTOP-JBKL5J0' |
| 0x3e | `04 65 0a 0a` | Address 1: IPv4 (reversed) | 10.10.101.4 |
| 0x42 | `2e 09` | Address 1: port | 2350 |
| 0x44 | `04 65 0a 0a` | Address 2: IPv4 (reversed) | 10.10.101.4 |
| 0x48 | `2e 09` | Address 2: port | 2350 |

---

## 11. Robust detection of a server

A host runs one of these games if and only if **all** of the following hold:

1. The UDP discovery query for one of the three game ids is answered with a type 1 message with a **valid checksum**
   and the matching nonce. *(Sufficient on its own for detection and game identification.)*
2. For the details: a TCP connection to the game port is possible, the reply frame has a valid header and a
   **correct checksum** (the key is not public, so other services cannot produce it), type 3, subtype 6, matching
   `request_id`.
3. The game tag is `0x07` or `0x09` (`(t & 0xE0) == 0`), and the structure can be fully parsed with length checks.

A TrackMania Forever server discards both queries, because it requires a checksum with its own key for message
types 0–4 (derived from [Trackmania-Nations.md](Trackmania-Nations.md), not tested live). Its server info would also
fail the game tag check (`0x2D`).

---

## 12. Reference implementation (Python, standard library only)

Tested live against the Sunrise eXtreme server (discovery via broadcast and query). The generated requests are
byte-identical to the ones in [Section 10](#10-annotated-examples-real-capture).
Usage: `python tms_query.py discover [broadcast address]` or `python tms_query.py <host> [port]`.

```python
"""TrackMania Original/Sunrise/Nations ESWC server query - minimal reference implementation (stdlib only)."""
import hashlib
import hmac
import secrets
import socket
import struct

KEY = bytes.fromhex("08c481303a1226abaf1d6ae4fb65fbc9")
GAMES = {"TmOriginal": 4, "TmSunrise": 4, "TmNationsESWC": 5}        # game id -> ConnectionAdmin version
GAME_MODES = {1: "TimeAttack", 3: "Rounds", 6: "Team", 7: "Laps", 8: "Stunts"}


def checksum(message: bytes, pos: int) -> int:
    data = bytearray(message)
    data[pos:pos + 4] = bytes(4)                     # checksum field counts as 0
    w = struct.unpack("<4I", hmac.new(KEY, bytes(data), hashlib.md5).digest())
    return (w[0] + w[1] + w[2] + struct.unpack_from("<I", KEY)[0]) & 0xFFFFFFFF


def build_message(msg_type: int, payload: bytes) -> bytes:
    msg = bytearray([0x82, msg_type]) + bytes(4) + payload   # flags 0x80 | 0x02 (checksum)
    msg[2:6] = struct.pack("<I", checksum(msg, 2))
    return bytes(msg)


def connection_admin(version: int, subtype: int, *args: int) -> bytes:
    msg = build_message(3, struct.pack(f"<II{len(args)}I", version, subtype, *args))
    return struct.pack("<I", len(msg)) + msg          # TCP frame: u32 length


def pack_str(text: str) -> bytes:
    data = text.encode()
    return struct.pack("<I", len(data)) + data


def lzo1x_decompress(src: bytes, size: int) -> bytes:
    out, ip, state = bytearray(), 0, 0

    def run(base):                                   # extended length: each 0 byte adds 255
        nonlocal ip
        n = 0
        while src[ip] == 0:
            n += 255
            ip += 1
        n += base + src[ip]
        ip += 1
        return n

    def literals(n):
        nonlocal ip
        out.extend(src[ip:ip + n])
        ip += n

    def match(pos, n):
        if pos < 0:
            raise ValueError("bad LZO distance")
        for i in range(n):                           # byte by byte: source may overlap
            out.append(out[pos + i])

    if src[0] > 17:                                  # first byte > 17: initial literal run
        n = src[0] - 17
        ip = 1
        literals(n)
        state = n if n < 4 else 4
    while True:
        t = src[ip]
        ip += 1
        if t < 16:
            if state == 0:                           # literal run
                literals((t or run(15)) + 3)
                state = 4
                continue
            d = (t >> 2) + (src[ip] << 2)
            ip += 1
            if state == 4:
                match(len(out) - 0x801 - d, 3)       # M1 directly after a literal run
            else:
                match(len(out) - 1 - d, 2)           # M1 after a match
        elif t >= 64:                                # M2
            d = ((t >> 2) & 7) + (src[ip] << 3)
            ip += 1
            match(len(out) - 1 - d, (t >> 5) + 1)
        elif t >= 32:                                # M3
            n = (t & 31 or run(31)) + 2
            d = (src[ip] | src[ip + 1] << 8) >> 2
            ip += 2
            match(len(out) - 1 - d, n)
        else:                                        # M4 (16..31), distance 0 = end of stream
            n = (t & 7 or run(7)) + 2
            d = ((t & 8) << 11) + ((src[ip] | src[ip + 1] << 8) >> 2)
            ip += 2
            if d == 0:
                break
            match(len(out) - d - 0x4000, n)
        state = src[ip - 2] & 3                      # 0-3 literals follow the match
        if state:
            literals(state)
    if len(out) != size:
        raise ValueError("LZO size mismatch")
    return bytes(out)


def decode_message(msg: bytes):
    flags, msg_type, pos = msg[0], msg[1], 2
    if flags & 0xF0 != 0x80:
        raise ValueError("bad flags")
    if flags & 0x0C:
        pos += 2                                     # u16 sequence number
    if not flags & 0x02 or struct.unpack_from("<I", msg, pos)[0] != checksum(msg, pos):
        raise ValueError("bad checksum")             # servers always set the checksum
    pos += 4
    if flags & 0x01:                                 # u32 uncompressed size + LZO1X stream
        size = struct.unpack_from("<I", msg, pos)[0]
        return msg_type, lzo1x_decompress(msg[pos + 4:], size)
    return msg_type, msg[pos:]


class Reader:
    def __init__(self, data):
        self.d, self.p = data, 0

    def take(self, n):
        if n < 0 or self.p + n > len(self.d):
            raise ValueError("truncated")
        self.p += n
        return self.d[self.p - n:self.p]

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def str(self):                                   # str and wstr: UTF-8, BOM if non-ASCII
        return self.take(self.u32()).decode("utf-8-sig", "replace")

    def addr(self):
        return ".".join(map(str, reversed(self.take(4)))), self.u16()


def parse_server_info(data: bytes) -> dict:
    r = Reader(data)
    tag = r.u8()
    if tag & 0xE0 != 0 or tag & 0x1F not in (0x07, 0x09):
        raise ValueError("not a TrackMania Original/Sunrise/Nations ESWC server")
    info = {"game_tag": tag, "address": r.addr(), "host_login": r.str()}
    login = r.str()                                  # "#SRV#" + "" / "p" / "s" / "f"
    if not login.startswith("#SRV#"):
        return info
    info["player_password"] = login[5:6] in ("p", "f")
    info["spectator_password"] = login[5:6] in ("s", "f")
    r.str()                                          # unused, always empty
    for key in ("players", "max_players", "spectators", "max_spectators", "ladder_mode"):
        info[key] = r.u8()
    info["name"] = r.str()
    names = [r.str() for _ in range(r.u32())]
    info["player_list"] = [(name, r.i32()) for name in names]   # (nickname, ladder ranking)
    info["comment"] = r.str()
    if r.p == len(data):
        return info
    mode = r.u8()
    info["game_mode"] = GAME_MODES.get(mode, f"Unknown ({mode})")
    info["mode_limit"] = r.u32()                     # ms (TA/Stunts), laps (Laps), points (Rounds/Team)
    info["nb_challenges"] = r.u8()
    info["challenges"] = [
        {"name": r.str(), "decoration_index": r.u32(), "gold_time": r.u32(), "copper_price": r.u32()}
        for _ in range(r.u32())
    ]
    return info


def query_info(host: str, port: int = 2350, version: int = 4, timeout: float = 5.0) -> dict:
    request_id = secrets.randbelow(0x7FFFFFFF) + 1
    with socket.create_connection((host, port), timeout) as s:
        s.sendall(connection_admin(version, 8) + connection_admin(version, 7, request_id))
        f = s.makefile("rb")
        while True:
            (length,) = struct.unpack("<I", f.read(4))
            if not 2 <= length <= 0x100000:
                raise ValueError("bad frame length")
            msg_type, payload = decode_message(f.read(length))
            if msg_type != 3:
                continue
            r = Reader(payload)
            server_version, subtype = r.u32(), r.u32()
            if subtype == 1:                         # refused, e.g. "Please upgrade your application."
                if server_version != version and server_version in (4, 5):
                    return query_info(host, port, server_version, timeout)
                raise ValueError("query refused")
            if subtype != 6:
                continue
            reply_id, data = r.u32(), r.take(r.u32())
            if reply_id == 0xFFFFFFFF:
                raise ValueError("server has no game info yet")
            if reply_id == request_id:
                return parse_server_info(data)


def discover(address: str = "255.255.255.255", port: int = 2350, timeout: float = 2.0) -> list:
    """LAN discovery: a server only answers the session query for its own game id."""
    nonce = secrets.randbits(32)
    sessions = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(timeout)
        for game_id in GAMES:
            query = pack_str(game_id) + pack_str("client") + bytes(6) + struct.pack("<I", nonce)
            s.sendto(build_message(0, query), (address, port))
        try:
            while True:
                datagram, sender = s.recvfrom(4096)
                try:
                    msg_type, payload = decode_message(datagram)
                except ValueError:
                    continue
                r = Reader(payload)
                if msg_type != 1 or r.u32() != nonce:
                    continue
                sessions.append({
                    "sender": sender[0], "application": r.str(), "game_id": r.str(),
                    "version": r.str(), "host_name": r.str(), "address": r.addr(),
                    "secondary_address": r.addr(),
                })
        except socket.timeout:
            pass
    return sessions


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2 or sys.argv[1] == "discover":
        print(json.dumps(discover(*sys.argv[2:3]), indent=2, ensure_ascii=False))
    else:
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 2350
        print(json.dumps(query_info(sys.argv[1], port), indent=2, ensure_ascii=False))
```

**Self-test:** the following expressions must evaluate to true.

```python
connection_admin(4, 8).hex()         == "0e00000082038b9433740400000008000000"
connection_admin(4, 7, 0x1234).hex() == "12000000820346e5b853040000000700000034120000"
```

The response from [Section 10](#10-annotated-examples-real-capture) must, after `decode_message(...)[1][16:]` and
`parse_server_info`, yield the name `Sunrise LAN Server`, TimeAttack with 300000 ms and the map `NightFlight`
(gold 39150, copper 1451).

---

## 13. Differences to TrackMania Forever

| Aspect | TrackMania Original/Sunrise/Nations ESWC | TrackMania Forever (TMNF/TMUF) |
|---|---|---|
| Framing, flags, LZO1X, query flow 8 → 7 → 6 | identical | identical |
| HMAC key | `08c481303a1226abaf1d6ae4fb65fbc9` | `b89dd780726b21ba98954315fa1cece1` |
| Checksum reduction | `w0 + w1 + w2 + key[0]` | `w0 + w1 + w2 + w3` |
| Checksum required for type 3 | no (still always sent by the server) | yes |
| ConnectionAdmin version | 4 (Original, Sunrise), 5 (Nations ESWC), exact match | 7 |
| Game tag | `0x07` / `0x09`, `(tag & 0xE0) == 0` | `0x2D`, `(tag & 0xE0) == 0x20` |
| Pack mask | – | `str` after the server name |
| Map entry | `wstr name, u32 decoration, u32 gold, u32 copper` | `wstr name, u32 gold, u16 copper, u8 env index` |
| Environment list | – | `u32 k` + lookback string ids |
| Game modes | 1, 3, 6, 7, 8 | 1, 3, 6, 7, 8, 9 (Cup) |
| Game identification | UDP discovery game id (`TmOriginal`, `TmSunrise`, `TmNationsESWC`) | pack mask |

---

## 14. Verification status

| Aspect | Static (Ghidra) | Live (Sunrise eXtreme, Windows) |
|---|:-:|:-:|
| Framing, flags, type 3 | ✅ | ✅ |
| HMAC-MD5 checksum incl. key word | ✅ | ✅ (requests and replies) |
| Request without checksum accepted | ✅ | ✅ |
| LZO1X | ✅ | ✅ |
| Flow subtype 8 → 7 → 6 in one write | ✅ | ✅ |
| Version 4, refusal for lower and silence for higher versions | ✅ | ✅ |
| Game tag `0x07` | ✅ | ✅ |
| Counters, name, comment, mode, limit | ✅ | ✅ (no players connected) |
| Window of 20 maps, map entry layout | ✅ | ✅ (54 → 20) |
| GoldTime / CopperPrice semantics | ✅ | plausible values |
| UDP discovery (unicast and broadcast), game id filter | ✅ | ✅ (`TmSunrise` answered, `TmOriginal`/`TmNationsESWC` not) |
| `#SRV#p` / `s` / `f` | ✅ | – (only `#SRV#` observed) |
| Player list with names and rankings, Unicode + BOM | ✅ | – |
| Nations ESWC (version 5, tag `0x09`, `TmNationsESWC`) | ✅ | – |
| TrackMania Original (`TmOriginal`) | ✅ | – |
| Other game modes than TimeAttack | ✅ | – |

---

## 15. Ghidra index (addresses, class IDs)

Binary: `TrackManiaServer.exe` (TrackMania Sunrise eXtreme dedicated server), image base `0x00400000`.
Functions created or named during the analysis: `CNetFormConnectionAdmin_Decode` (`0x004b2070`),
`CNetFormQuerrySessions_Decode`/`_Archive` (`0x004b1260`/`0x004b11e0`), `CNetFormEnumSessions_Decode`/`_Archive`
(`0x004b1460`/`0x004b1430`), `CNetServerInfo_Archive` (`0x004aa410`), `CTrackManiaNetworkServerInfo_Archive`
(`0x0069a940`), `CTrackManiaNetworkServerInfo_ArchiveModeLimit` (`0x0069a8a0`), `XmlRpc_SetServerPassword`
(`0x00626320`), `XmlRpc_SetServerPasswordForSpectator` (`0x00626470`).

### 15.1 Game selection and network layer

| Address | Function | Purpose |
|---|---|---|
| `0x00401d60` | `/game=` option | `Sunrise` → `TmSunrise`, `Original` → `TmOriginal`, `Nations` → `TmNationsESWC` (global `0x008c921c` = 2/1/4) |
| `0x004afc70` | CNetConnection::TcpReceive | `u32` length prefix, assemble message |
| `0x004a9730` | Decode message | flags, type table, sequence, checksum, LZO, instantiation |
| `0x004a9370` | Encode message | counterpart for sending |
| `0x00419310` | HMAC-MD5 | key from caller; sum at `0x004a9972` |
| `0x00854f74` | Data | HMAC key (16 bytes) |
| `0x006f10e0` | lzo1x_decompress_safe | decompression |
| `0x007f2130` | Data | message type table (8 DWORDs per entry) |
| `0x004b86d0` | ConnectionAdmin handler | exact version check, subtypes 0/4/8/9, "Please upgrade" |
| `0x004b81d0` | CNetServer UDP receive | QuerrySessions → game id check (`0x004b8430`) → EnumSessions |

### 15.2 ConnectionAdmin and query

| Address | Function | Purpose |
|---|---|---|
| `0x004b1b30` | Class registration | `0x12010000` "CNetFormConnectionAdmin", factory `0x004b1b50` |
| `0x004b1cf0` / `0x004b1cd0` | Constructor / version | version 4 (Original, Sunrise) or 5 |
| `0x004b2070` | Decoder | version and per-subtype size checks |
| `0x004b1dd0` | Archive (vtable `0x007e64d0` + `0x3c`) | fields per subtype |
| `0x0074d940` | Info reply | subtype 6, `0xFFFFFFFF` if no info |

### 15.3 Server info

| Address | Function | Purpose |
|---|---|---|
| `0x004c8870` | CNetMasterHost (vtable `0x007e7120` + `0x88`) | game tag `+0x14`, address, login `+0x28` |
| `0x004c87b0` / `0x0069acb0` | Tag checks | valid / game (7 or 9) |
| `0x0074cb80` | CGameNetServerInfo (vtable `0x007fefb0` + `0x88`) | `#SRV#` login `+0x78` |
| `0x0074cd90` | `#SRV#` login | password flags p/s/f |
| `0x006ac250` / `0x006ac480` | Game server info | players, comment / counters, name |
| `0x0069a940` | CTrackManiaNetworkServerInfo (vtable `0x007f4ce0` + `0x88`) | mode, limit, challenge window |
| `0x0069ac50` / `0x0069a8a0` | Mode / limit | `u8` mode, `u32` mode-dependent limit |
| `0x0069ad50` | Map entry | name, decoration index, gold time, copper price |
| `0x0069ae00` | Mode mapping | XML-RPC → internal ID |
| `0x005e24b0` | GetParam of challenge info `0x2400B000` | `CollectionId2` = `+0x74` |
| `0x005e2af0` / `0x005eb450` | Decoration index | 2 + table index of the decoration ident |
| `0x00657960` | GetChallengeList (copy loop) | environment `+0x38`, mood `+0x40`, gold `+0x58`, copper `+0x64` |
| `0x005ddc30` | Client "FrameDialogJoin" | consumer of the challenge window |

### 15.4 UDP discovery

| Address | Function | Purpose |
|---|---|---|
| `0x004b11e0` / `0x004b1260` | QuerrySessions archive / decoder | vtable `0x007e6388` |
| `0x004b1430` / `0x004b1460` | EnumSessions archive / decoder | vtable `0x007e62e8` |
| `0x004aa410` | CNetServerInfo archive | 4 × `str`, 2 × `addr` |
| `0x0074d430` | CGameNetwork constructor | registers "GameNet", game id and version |

### 15.5 Class IDs

| Class | ID |
|---|---|
| CNetServerInfo | `0x12002000` |
| CNetFormQuerrySessions | `0x12007000` |
| CNetFormEnumSessions | `0x12008000` |
| CNetFormPing | `0x12009000` |
| CNetFormConnectionAdmin | `0x12010000` |
| CNetMasterHost | `0x12015000` |
| CGameNetServerInfo | `0x0302E000` |
| CTrackManiaNetworkServerInfo | `0x24035000` |
| Challenge info (client/server list) | `0x2400B000` |

---

## 16. Existing implementations

| Project | File | Status |
|---|---|---|
| opengsq-python | `opengsq/protocols/trackmania_sunrise.py`, `opengsq/responses/trackmania_sunrise/server_info.py`, tests `tests/protocols/test_trackmania_sunrise.py` | Implemented based on this document (branch `feature/trackmania-sunrise-protocol`). `get_info()` (TCP, automatic version 4/5) and `get_session()` (UDP, game identification). |
| Discord-Gameserver-Notifier | `src/discord_gameserver_notifier/discovery/protocols/trackmania_sunrise.py` | Game type `trackmania_sunrise`: UDP broadcast discovery for all three game ids, then TCP query; uses opengsq. |
