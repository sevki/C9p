# C9p

A 9P2000 protocol implementation in **Carbon**.

## Design: sans-IO

The Carbon codec (`carbon/p9.carbon`) performs **zero** network or file I/O.
Every function either:

- accepts typed values and writes bytes into an `Encoder` buffer, or
- accepts raw bytes in a `Decoder` buffer and returns typed values.

The caller owns all transport concerns: read bytes from the network into
`dec.buf`, call `DecodeHeader` + `DecodeTxxx`, act on the result, call
`EncodeRxxx`, then write `enc.buf[0..enc.pos]` back to the network.
No sockets, threads, or OS calls are touched by the codec itself.

This approach makes the Carbon codec portable to any host environment
regardless of what I/O primitives (if any) Carbon's stdlib exposes at a
given toolchain revision.

## Structure

```
carbon/p9.carbon   — Carbon sans-IO codec (all 13 T/R message pairs)
protocol/          — Go reference implementation (types, server, client)
```

## Building the Carbon codec

```sh
# Install the Carbon nightly toolchain from:
# https://github.com/carbon-language/carbon-lang/releases
carbon compile --output=p9.o carbon/p9.carbon
carbon link    --output=p9   p9.o
./p9   # exits 0 on success (smoke-tests Tversion round-trip)
```

## Protocol coverage

| Message pair | Encode | Decode |
|---|---|---|
| Tversion / Rversion | ✓ | ✓ |
| Tattach / Rattach   | ✓ | ✓ |
| Rerror              | ✓ | ✓ |
| Tflush / Rflush     | ✓ | ✓ |
| Twalk / Rwalk       | ✓ | ✓ |
| Topen / Ropen       | ✓ | ✓ |
| Tcreate / Rcreate   | ✓ | ✓ |
| Tread / Rread       | ✓ | ✓ |
| Twrite / Rwrite     | ✓ | ✓ |
| Tclunk / Rclunk     | ✓ | ✓ |
| Tremove / Rremove   | ✓ | ✓ |
| Tstat / Rstat       | ✓ | ✓ |
| Twstat / Rwstat     | ✓ | ✓ |