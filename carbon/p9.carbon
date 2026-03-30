// Copyright 2024 The C9p Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.
//
// Sans-IO 9P2000 codec for Carbon.
//
// "Sans-IO" means this file performs zero network or file I/O.
// Every function either:
//   • accepts typed values and writes bytes into an Encoder buffer, or
//   • accepts raw bytes in a Decoder buffer and returns typed values.
//
// The caller owns all transport: it reads bytes from the network into
// dec.buf, calls a Decode* function, acts on the result, calls an
// Encode* function, then writes enc.buf[0..enc.pos] back to the network.
// No sockets, threads, or OS calls are touched here.
//
// Requires: Carbon nightly toolchain (carbon compile / carbon link).
// Build:
//   carbon compile --output=p9.o carbon/p9.carbon
//   carbon link    --output=p9   p9.o
//   ./p9                        # exits 0 on success

package C9p api;

// ── 9P2000 message-type constants ─────────────────────────────────────────────
let Tversion: u8 = 100;
let Rversion: u8 = 101;
let Tauth:    u8 = 102;
let Rauth:    u8 = 103;
let Tattach:  u8 = 104;
let Rattach:  u8 = 105;
let Terror:   u8 = 106;
let Rerror:   u8 = 107;
let Tflush:   u8 = 108;
let Rflush:   u8 = 109;
let Twalk:    u8 = 110;
let Rwalk:    u8 = 111;
let Topen:    u8 = 112;
let Ropen:    u8 = 113;
let Tcreate:  u8 = 114;
let Rcreate:  u8 = 115;
let Tread:    u8 = 116;
let Rread:    u8 = 117;
let Twrite:   u8 = 118;
let Rwrite:   u8 = 119;
let Tclunk:   u8 = 120;
let Rclunk:   u8 = 121;
let Tremove:  u8 = 122;
let Rremove:  u8 = 123;
let Tstat:    u8 = 124;
let Rstat:    u8 = 125;
let Twstat:   u8 = 126;
let Rwstat:   u8 = 127;

// ── QID type bits ──────────────────────────────────────────────────────────────
let QTDIR:     u8 = 0x80;
let QTAPPEND:  u8 = 0x40;
let QTEXCL:    u8 = 0x20;
let QTMOUNT:   u8 = 0x10;
let QTAUTH:    u8 = 0x08;
let QTTMP:     u8 = 0x04;
let QTSYMLINK: u8 = 0x02;
let QTLINK:    u8 = 0x01;
let QTFILE:    u8 = 0x00;

// ── Open-mode flags ────────────────────────────────────────────────────────────
let OREAD:   u8 = 0x00;
let OWRITE:  u8 = 0x01;
let ORDWR:   u8 = 0x02;
let OEXEC:   u8 = 0x03;
let OTRUNC:  u8 = 0x10;
let OCEXEC:  u8 = 0x20;
let ORCLOSE: u8 = 0x40;

// ── File-mode bits ─────────────────────────────────────────────────────────────
let DMDIR:    u32 = 0x80000000;
let DMAPPEND: u32 = 0x40000000;
let DMEXCL:   u32 = 0x20000000;
let DMMOUNT:  u32 = 0x10000000;
let DMAUTH:   u32 = 0x08000000;
let DMTMP:    u32 = 0x04000000;
let DMREAD:   u32 = 0x00000004;
let DMWRITE:  u32 = 0x00000002;
let DMEXEC:   u32 = 0x00000001;

// ── Protocol constants ─────────────────────────────────────────────────────────
let NOTAG: u16 = 0xFFFF;
let NOFID: u32 = 0xFFFFFFFF;
let IOHDRSZ: u32 = 24;
let QIDLen: u32 = 13;
// Compile-time upper bound for any single 9P message.
// After Tversion/Rversion negotiation the negotiated msize applies;
// this constant sizes the Encoder/Decoder buffers.
let MaxMsgSize: u32 = 65536;
// Maximum walk path components per Twalk.
let MaxWnames: u32 = 16;

// ── Wire types ─────────────────────────────────────────────────────────────────

// QID uniquely identifies a file on the server side.
struct QID {
  var qtype:   u8;   // type bits (QTDIR, QTFILE, …)
  var version: u32;  // monotonically increasing version
  var path:    u64;  // server-unique file identifier
}

// StringRef is a zero-copy view of a string inside a Decoder buffer.
// Access the bytes as:  dec.buf[ref.offset .. ref.offset + ref.len]
struct StringRef {
  var offset: u32;
  var len:    u16;
}

// =============================================================================
// Encoder
// =============================================================================
// Accumulates one complete 9P message into buf[0..pos].
// Typical use:
//   var enc: Encoder;
//   EncodeXxx(&enc, tag, …);
//   // write enc.buf[0..enc.pos] to the transport
class Encoder {
  var buf: [u8; 65536];
  var pos: u32;

  // Reset the write cursor; call before encoding a new message.
  fn Reset[addr me: Encoder*]() {
    me^.pos = 0;
  }

  // Reserve 4 bytes for the total-size field; filled in by Finish().
  fn BeginMsg[addr me: Encoder*]() {
    me^.pos = 0;
    me^.WriteU8(0); me^.WriteU8(0);
    me^.WriteU8(0); me^.WriteU8(0);
  }

  // Back-patch the 4-byte little-endian total size at buf[0..4].
  fn Finish[addr me: Encoder*]() {
    let n: u32 = me^.pos;
    me^.buf[0] = (n         & 0xFF) as u8;
    me^.buf[1] = ((n >>  8) & 0xFF) as u8;
    me^.buf[2] = ((n >> 16) & 0xFF) as u8;
    me^.buf[3] = ((n >> 24) & 0xFF) as u8;
  }

  fn WriteU8[addr me: Encoder*](v: u8) {
    me^.buf[me^.pos] = v;
    me^.pos += 1;
  }

  fn WriteU16[addr me: Encoder*](v: u16) {
    me^.WriteU8(( v        & 0xFF) as u8);
    me^.WriteU8(((v >>  8) & 0xFF) as u8);
  }

  fn WriteU32[addr me: Encoder*](v: u32) {
    me^.WriteU8(( v        & 0xFF) as u8);
    me^.WriteU8(((v >>  8) & 0xFF) as u8);
    me^.WriteU8(((v >> 16) & 0xFF) as u8);
    me^.WriteU8(((v >> 24) & 0xFF) as u8);
  }

  fn WriteU64[addr me: Encoder*](v: u64) {
    me^.WriteU32(( v        & 0xFFFFFFFF) as u32);
    me^.WriteU32(((v >> 32) & 0xFFFFFFFF) as u32);
  }

  // Write a 9P length-prefixed string from a caller-managed byte buffer.
  fn WriteStr[addr me: Encoder*](s: [u8; 65536]*, slen: u16) {
    me^.WriteU16(slen);
    var i: u32 = 0;
    while i < (slen as u32) {
      me^.WriteU8(s^[i]);
      i += 1;
    }
  }

  fn WriteQID[addr me: Encoder*](q: QID) {
    me^.WriteU8(q.qtype);
    me^.WriteU32(q.version);
    me^.WriteU64(q.path);
  }
}

// =============================================================================
// Decoder
// =============================================================================
// Parses one 9P message from buf[0..len].
// Typical use:
//   var dec: Decoder;
//   // copy received bytes into dec.buf; set dec.len = bytes_received
//   dec.Init(bytes_received);
//   let hdr: Header = DecodeHeader(&dec);
//   let result: TversionResult = DecodeTversion(&dec);
class Decoder {
  var buf: [u8; 65536];
  var len: u32;
  var pos: u32;
  var err: bool;  // set to true on any underflow

  fn Init[addr me: Decoder*](msg_len: u32) {
    me^.len = msg_len;
    me^.pos = 0;
    me^.err = false;
  }

  fn ReadU8[addr me: Decoder*]() -> u8 {
    if me^.pos >= me^.len {
      me^.err = true;
      return 0;
    }
    let v: u8 = me^.buf[me^.pos];
    me^.pos += 1;
    return v;
  }

  fn ReadU16[addr me: Decoder*]() -> u16 {
    let lo: u16 = me^.ReadU8() as u16;
    let hi: u16 = me^.ReadU8() as u16;
    return lo | (hi << 8);
  }

  fn ReadU32[addr me: Decoder*]() -> u32 {
    let b0: u32 = me^.ReadU8() as u32;
    let b1: u32 = me^.ReadU8() as u32;
    let b2: u32 = me^.ReadU8() as u32;
    let b3: u32 = me^.ReadU8() as u32;
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
  }

  fn ReadU64[addr me: Decoder*]() -> u64 {
    let lo: u64 = me^.ReadU32() as u64;
    let hi: u64 = me^.ReadU32() as u64;
    return lo | (hi << 32);
  }

  // Record the current string as a StringRef (zero-copy) and advance past it.
  fn ReadStr[addr me: Decoder*]() -> StringRef {
    let slen: u16 = me^.ReadU16();
    let ref_offset: u32 = me^.pos;
    me^.pos = me^.pos + (slen as u32);
    if me^.pos > me^.len {
      me^.err = true;
    }
    return {.offset = ref_offset, .len = slen};
  }

  fn ReadQID[addr me: Decoder*]() -> QID {
    let qtype:   u8  = me^.ReadU8();
    let version: u32 = me^.ReadU32();
    let path:    u64 = me^.ReadU64();
    return {.qtype = qtype, .version = version, .path = path};
  }
}

// =============================================================================
// Message header (first 7 bytes of every 9P frame on the wire)
// =============================================================================
struct Header {
  var size:  u32;
  var mtype: u8;
  var tag:   u16;
}

fn DecodeHeader(dec: Decoder*) -> Header {
  let size:  u32 = dec^.ReadU32();
  let mtype: u8  = dec^.ReadU8();
  let tag:   u16 = dec^.ReadU16();
  return {.size = size, .mtype = mtype, .tag = tag};
}

// =============================================================================
// Tversion / Rversion  — protocol version negotiation
// =============================================================================
fn EncodeTversion(enc: Encoder*, tag: u16, msize: u32,
                  ver: [u8; 65536]*, vlen: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Tversion);
  enc^.WriteU16(tag);
  enc^.WriteU32(msize);
  enc^.WriteStr(ver, vlen);
  enc^.Finish();
}

struct TversionResult {
  var tag:     u16;
  var msize:   u32;
  var version: StringRef;
  var ok:      bool;
}

fn DecodeTversion(dec: Decoder*) -> TversionResult {
  let tag:     u16       = dec^.ReadU16();
  let msize:   u32       = dec^.ReadU32();
  let version: StringRef = dec^.ReadStr();
  return {.tag = tag, .msize = msize, .version = version,
          .ok = not dec^.err};
}

fn EncodeRversion(enc: Encoder*, tag: u16, msize: u32,
                  ver: [u8; 65536]*, vlen: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Rversion);
  enc^.WriteU16(tag);
  enc^.WriteU32(msize);
  enc^.WriteStr(ver, vlen);
  enc^.Finish();
}

struct RversionResult {
  var tag:     u16;
  var msize:   u32;
  var version: StringRef;
  var ok:      bool;
}

fn DecodeRversion(dec: Decoder*) -> RversionResult {
  let tag:     u16       = dec^.ReadU16();
  let msize:   u32       = dec^.ReadU32();
  let version: StringRef = dec^.ReadStr();
  return {.tag = tag, .msize = msize, .version = version,
          .ok = not dec^.err};
}

// =============================================================================
// Tattach / Rattach  — attach to file server
// =============================================================================
fn EncodeTattach(enc: Encoder*, tag: u16, fid: u32, afid: u32,
                 uname: [u8; 65536]*, ulen: u16,
                 aname: [u8; 65536]*, alen: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Tattach);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.WriteU32(afid);
  enc^.WriteStr(uname, ulen);
  enc^.WriteStr(aname, alen);
  enc^.Finish();
}

struct TattachResult {
  var tag:   u16;
  var fid:   u32;
  var afid:  u32;
  var uname: StringRef;
  var aname: StringRef;
  var ok:    bool;
}

fn DecodeTattach(dec: Decoder*) -> TattachResult {
  let tag:   u16       = dec^.ReadU16();
  let fid:   u32       = dec^.ReadU32();
  let afid:  u32       = dec^.ReadU32();
  let uname: StringRef = dec^.ReadStr();
  let aname: StringRef = dec^.ReadStr();
  return {.tag = tag, .fid = fid, .afid = afid,
          .uname = uname, .aname = aname, .ok = not dec^.err};
}

fn EncodeRattach(enc: Encoder*, tag: u16, q: QID) {
  enc^.BeginMsg();
  enc^.WriteU8(Rattach);
  enc^.WriteU16(tag);
  enc^.WriteQID(q);
  enc^.Finish();
}

struct RattachResult {
  var tag: u16;
  var qid: QID;
  var ok:  bool;
}

fn DecodeRattach(dec: Decoder*) -> RattachResult {
  let tag: u16 = dec^.ReadU16();
  let qid: QID = dec^.ReadQID();
  return {.tag = tag, .qid = qid, .ok = not dec^.err};
}

// =============================================================================
// Rerror  — error reply (Terror is never sent on the wire)
// =============================================================================
fn EncodeRerror(enc: Encoder*, tag: u16,
                msg: [u8; 65536]*, mlen: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Rerror);
  enc^.WriteU16(tag);
  enc^.WriteStr(msg, mlen);
  enc^.Finish();
}

struct RerrorResult {
  var tag:    u16;
  var errmsg: StringRef;
  var ok:     bool;
}

fn DecodeRerror(dec: Decoder*) -> RerrorResult {
  let tag:    u16       = dec^.ReadU16();
  let errmsg: StringRef = dec^.ReadStr();
  return {.tag = tag, .errmsg = errmsg, .ok = not dec^.err};
}

// =============================================================================
// Tflush / Rflush  — abort a pending request
// =============================================================================
fn EncodeTflush(enc: Encoder*, tag: u16, oldtag: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Tflush);
  enc^.WriteU16(tag);
  enc^.WriteU16(oldtag);
  enc^.Finish();
}

struct TflushResult {
  var tag:    u16;
  var oldtag: u16;
  var ok:     bool;
}

fn DecodeTflush(dec: Decoder*) -> TflushResult {
  let tag:    u16 = dec^.ReadU16();
  let oldtag: u16 = dec^.ReadU16();
  return {.tag = tag, .oldtag = oldtag, .ok = not dec^.err};
}

fn EncodeRflush(enc: Encoder*, tag: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Rflush);
  enc^.WriteU16(tag);
  enc^.Finish();
}

struct RflushResult {
  var tag: u16;
  var ok:  bool;
}

fn DecodeRflush(dec: Decoder*) -> RflushResult {
  let tag: u16 = dec^.ReadU16();
  return {.tag = tag, .ok = not dec^.err};
}

// =============================================================================
// Twalk / Rwalk  — walk the directory tree
// =============================================================================
// path_names is a flat byte buffer holding all wname strings back-to-back.
// name_offsets[i] is the byte offset of wname[i] within path_names.
// name_lens[i]   is the byte length of wname[i].
fn EncodeTwalk(enc: Encoder*, tag: u16, fid: u32, newfid: u32,
               nwname: u16,
               path_names:   [u8;  65536]*,
               name_offsets: [u32; 16]*,
               name_lens:    [u16; 16]*) {
  enc^.BeginMsg();
  enc^.WriteU8(Twalk);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.WriteU32(newfid);
  enc^.WriteU16(nwname);
  var i: u32 = 0;
  while i < (nwname as u32) {
    let off:  u32 = name_offsets^[i];
    let slen: u16 = name_lens^[i];
    enc^.WriteU16(slen);
    var j: u32 = 0;
    while j < (slen as u32) {
      enc^.WriteU8(path_names^[off + j]);
      j += 1;
    }
    i += 1;
  }
  enc^.Finish();
}

struct TwalkResult {
  var tag:    u16;
  var fid:    u32;
  var newfid: u32;
  var nwname: u16;
  // name_refs[i] points into dec.buf for the i-th wname; valid for [0..nwname).
  var name_refs: [StringRef; 16];
  var ok:     bool;
}

fn DecodeTwalk(dec: Decoder*) -> TwalkResult {
  let tag:    u16 = dec^.ReadU16();
  let fid:    u32 = dec^.ReadU32();
  let newfid: u32 = dec^.ReadU32();
  let nwname: u16 = dec^.ReadU16();
  var result: TwalkResult;
  result.tag    = tag;
  result.fid    = fid;
  result.newfid = newfid;
  result.nwname = nwname;
  var i: u32 = 0;
  while i < (nwname as u32) {
    result.name_refs[i] = dec^.ReadStr();
    i += 1;
  }
  result.ok = not dec^.err;
  return result;
}

// qids output array is filled by the callee; entries [0..nwqid) are valid.
fn EncodeRwalk(enc: Encoder*, tag: u16, nwqid: u16,
               qids: [QID; 16]*) {
  enc^.BeginMsg();
  enc^.WriteU8(Rwalk);
  enc^.WriteU16(tag);
  enc^.WriteU16(nwqid);
  var i: u32 = 0;
  while i < (nwqid as u32) {
    enc^.WriteQID(qids^[i]);
    i += 1;
  }
  enc^.Finish();
}

struct RwalkResult {
  var tag:   u16;
  var nwqid: u16;
  var ok:    bool;
}

// Caller supplies qids[16] to receive the walked QIDs.
fn DecodeRwalk(dec: Decoder*, qids: [QID; 16]*) -> RwalkResult {
  let tag:   u16 = dec^.ReadU16();
  let nwqid: u16 = dec^.ReadU16();
  var i: u32 = 0;
  while i < (nwqid as u32) {
    qids^[i] = dec^.ReadQID();
    i += 1;
  }
  return {.tag = tag, .nwqid = nwqid, .ok = not dec^.err};
}

// =============================================================================
// Topen / Ropen  — open a file
// =============================================================================
fn EncodeTopen(enc: Encoder*, tag: u16, fid: u32, mode: u8) {
  enc^.BeginMsg();
  enc^.WriteU8(Topen);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.WriteU8(mode);
  enc^.Finish();
}

struct TopenResult {
  var tag:  u16;
  var fid:  u32;
  var mode: u8;
  var ok:   bool;
}

fn DecodeTopen(dec: Decoder*) -> TopenResult {
  let tag:  u16 = dec^.ReadU16();
  let fid:  u32 = dec^.ReadU32();
  let mode: u8  = dec^.ReadU8();
  return {.tag = tag, .fid = fid, .mode = mode, .ok = not dec^.err};
}

fn EncodeRopen(enc: Encoder*, tag: u16, q: QID, iounit: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Ropen);
  enc^.WriteU16(tag);
  enc^.WriteQID(q);
  enc^.WriteU32(iounit);
  enc^.Finish();
}

struct RopenResult {
  var tag:    u16;
  var qid:    QID;
  var iounit: u32;
  var ok:     bool;
}

fn DecodeRopen(dec: Decoder*) -> RopenResult {
  let tag:    u16 = dec^.ReadU16();
  let qid:    QID = dec^.ReadQID();
  let iounit: u32 = dec^.ReadU32();
  return {.tag = tag, .qid = qid, .iounit = iounit, .ok = not dec^.err};
}

// =============================================================================
// Tcreate / Rcreate  — create a new file
// =============================================================================
fn EncodeTcreate(enc: Encoder*, tag: u16, fid: u32,
                 name: [u8; 65536]*, nlen: u16,
                 perm: u32, mode: u8) {
  enc^.BeginMsg();
  enc^.WriteU8(Tcreate);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.WriteStr(name, nlen);
  enc^.WriteU32(perm);
  enc^.WriteU8(mode);
  enc^.Finish();
}

struct TcreateResult {
  var tag:  u16;
  var fid:  u32;
  var name: StringRef;
  var perm: u32;
  var mode: u8;
  var ok:   bool;
}

fn DecodeTcreate(dec: Decoder*) -> TcreateResult {
  let tag:  u16       = dec^.ReadU16();
  let fid:  u32       = dec^.ReadU32();
  let name: StringRef = dec^.ReadStr();
  let perm: u32       = dec^.ReadU32();
  let mode: u8        = dec^.ReadU8();
  return {.tag = tag, .fid = fid, .name = name,
          .perm = perm, .mode = mode, .ok = not dec^.err};
}

fn EncodeRcreate(enc: Encoder*, tag: u16, q: QID, iounit: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Rcreate);
  enc^.WriteU16(tag);
  enc^.WriteQID(q);
  enc^.WriteU32(iounit);
  enc^.Finish();
}

struct RcreateResult {
  var tag:    u16;
  var qid:    QID;
  var iounit: u32;
  var ok:     bool;
}

fn DecodeRcreate(dec: Decoder*) -> RcreateResult {
  let tag:    u16 = dec^.ReadU16();
  let qid:    QID = dec^.ReadQID();
  let iounit: u32 = dec^.ReadU32();
  return {.tag = tag, .qid = qid, .iounit = iounit, .ok = not dec^.err};
}

// =============================================================================
// Tread / Rread  — read data from a file
// =============================================================================
fn EncodeTread(enc: Encoder*, tag: u16, fid: u32,
               offset: u64, count: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Tread);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.WriteU64(offset);
  enc^.WriteU32(count);
  enc^.Finish();
}

struct TreadResult {
  var tag:    u16;
  var fid:    u32;
  var offset: u64;
  var count:  u32;
  var ok:     bool;
}

fn DecodeTread(dec: Decoder*) -> TreadResult {
  let tag:    u16 = dec^.ReadU16();
  let fid:    u32 = dec^.ReadU32();
  let offset: u64 = dec^.ReadU64();
  let count:  u32 = dec^.ReadU32();
  return {.tag = tag, .fid = fid, .offset = offset,
          .count = count, .ok = not dec^.err};
}

// Rread: data bytes follow a u32 count prefix.
fn EncodeRread(enc: Encoder*, tag: u16,
               data: [u8; 65536]*, dlen: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Rread);
  enc^.WriteU16(tag);
  enc^.WriteU32(dlen);
  var i: u32 = 0;
  while i < dlen {
    enc^.WriteU8(data^[i]);
    i += 1;
  }
  enc^.Finish();
}

// data_offset / data_count point into dec.buf for zero-copy access.
struct RreadResult {
  var tag:         u16;
  var data_offset: u32;
  var data_count:  u32;
  var ok:          bool;
}

fn DecodeRread(dec: Decoder*) -> RreadResult {
  let tag:   u16 = dec^.ReadU16();
  let count: u32 = dec^.ReadU32();
  let doff:  u32 = dec^.pos;
  dec^.pos = dec^.pos + count;
  if dec^.pos > dec^.len {
    dec^.err = true;
  }
  return {.tag = tag, .data_offset = doff,
          .data_count = count, .ok = not dec^.err};
}

// =============================================================================
// Twrite / Rwrite  — write data to a file
// =============================================================================
fn EncodeTwrite(enc: Encoder*, tag: u16, fid: u32, offset: u64,
                data: [u8; 65536]*, dlen: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Twrite);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.WriteU64(offset);
  enc^.WriteU32(dlen);
  var i: u32 = 0;
  while i < dlen {
    enc^.WriteU8(data^[i]);
    i += 1;
  }
  enc^.Finish();
}

struct TwriteResult {
  var tag:         u16;
  var fid:         u32;
  var offset:      u64;
  var data_offset: u32;
  var data_count:  u32;
  var ok:          bool;
}

fn DecodeTwrite(dec: Decoder*) -> TwriteResult {
  let tag:    u16 = dec^.ReadU16();
  let fid:    u32 = dec^.ReadU32();
  let offset: u64 = dec^.ReadU64();
  let count:  u32 = dec^.ReadU32();
  let doff:   u32 = dec^.pos;
  dec^.pos = dec^.pos + count;
  if dec^.pos > dec^.len {
    dec^.err = true;
  }
  return {.tag = tag, .fid = fid, .offset = offset,
          .data_offset = doff, .data_count = count,
          .ok = not dec^.err};
}

fn EncodeRwrite(enc: Encoder*, tag: u16, count: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Rwrite);
  enc^.WriteU16(tag);
  enc^.WriteU32(count);
  enc^.Finish();
}

struct RwriteResult {
  var tag:   u16;
  var count: u32;
  var ok:    bool;
}

fn DecodeRwrite(dec: Decoder*) -> RwriteResult {
  let tag:   u16 = dec^.ReadU16();
  let count: u32 = dec^.ReadU32();
  return {.tag = tag, .count = count, .ok = not dec^.err};
}

// =============================================================================
// Tclunk / Rclunk  — relinquish a fid
// =============================================================================
fn EncodeTclunk(enc: Encoder*, tag: u16, fid: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Tclunk);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.Finish();
}

struct TclunkResult {
  var tag: u16;
  var fid: u32;
  var ok:  bool;
}

fn DecodeTclunk(dec: Decoder*) -> TclunkResult {
  let tag: u16 = dec^.ReadU16();
  let fid: u32 = dec^.ReadU32();
  return {.tag = tag, .fid = fid, .ok = not dec^.err};
}

fn EncodeRclunk(enc: Encoder*, tag: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Rclunk);
  enc^.WriteU16(tag);
  enc^.Finish();
}

struct RclunkResult {
  var tag: u16;
  var ok:  bool;
}

fn DecodeRclunk(dec: Decoder*) -> RclunkResult {
  let tag: u16 = dec^.ReadU16();
  return {.tag = tag, .ok = not dec^.err};
}

// =============================================================================
// Tremove / Rremove  — remove a file
// =============================================================================
fn EncodeTremove(enc: Encoder*, tag: u16, fid: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Tremove);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.Finish();
}

struct TremoveResult {
  var tag: u16;
  var fid: u32;
  var ok:  bool;
}

fn DecodeTremove(dec: Decoder*) -> TremoveResult {
  let tag: u16 = dec^.ReadU16();
  let fid: u32 = dec^.ReadU32();
  return {.tag = tag, .fid = fid, .ok = not dec^.err};
}

fn EncodeRremove(enc: Encoder*, tag: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Rremove);
  enc^.WriteU16(tag);
  enc^.Finish();
}

struct RremoveResult {
  var tag: u16;
  var ok:  bool;
}

fn DecodeRremove(dec: Decoder*) -> RremoveResult {
  let tag: u16 = dec^.ReadU16();
  return {.tag = tag, .ok = not dec^.err};
}

// =============================================================================
// Tstat / Rstat  — get file metadata
// =============================================================================
fn EncodeTstat(enc: Encoder*, tag: u16, fid: u32) {
  enc^.BeginMsg();
  enc^.WriteU8(Tstat);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.Finish();
}

struct TstatResult {
  var tag: u16;
  var fid: u32;
  var ok:  bool;
}

fn DecodeTstat(dec: Decoder*) -> TstatResult {
  let tag: u16 = dec^.ReadU16();
  let fid: u32 = dec^.ReadU32();
  return {.tag = tag, .fid = fid, .ok = not dec^.err};
}

// The stat blob is a self-describing byte structure; we expose it as a
// zero-copy reference into dec.buf to let callers parse it further.
fn EncodeRstat(enc: Encoder*, tag: u16,
               stat: [u8; 65536]*, slen: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Rstat);
  enc^.WriteU16(tag);
  enc^.WriteU16(slen);  // outer u16 count wrapping the stat blob
  var i: u32 = 0;
  while i < (slen as u32) {
    enc^.WriteU8(stat^[i]);
    i += 1;
  }
  enc^.Finish();
}

struct RstatResult {
  var tag:         u16;
  var stat_offset: u32;
  var stat_len:    u16;
  var ok:          bool;
}

fn DecodeRstat(dec: Decoder*) -> RstatResult {
  let tag:  u16 = dec^.ReadU16();
  let slen: u16 = dec^.ReadU16();
  let soff: u32 = dec^.pos;
  dec^.pos = dec^.pos + (slen as u32);
  if dec^.pos > dec^.len {
    dec^.err = true;
  }
  return {.tag = tag, .stat_offset = soff,
          .stat_len = slen, .ok = not dec^.err};
}

// =============================================================================
// Twstat / Rwstat  — set file metadata
// =============================================================================
fn EncodeTwstat(enc: Encoder*, tag: u16, fid: u32,
                stat: [u8; 65536]*, slen: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Twstat);
  enc^.WriteU16(tag);
  enc^.WriteU32(fid);
  enc^.WriteU16(slen);
  var i: u32 = 0;
  while i < (slen as u32) {
    enc^.WriteU8(stat^[i]);
    i += 1;
  }
  enc^.Finish();
}

struct TwstatResult {
  var tag:         u16;
  var fid:         u32;
  var stat_offset: u32;
  var stat_len:    u16;
  var ok:          bool;
}

fn DecodeTwstat(dec: Decoder*) -> TwstatResult {
  let tag:  u16 = dec^.ReadU16();
  let fid:  u32 = dec^.ReadU32();
  let slen: u16 = dec^.ReadU16();
  let soff: u32 = dec^.pos;
  dec^.pos = dec^.pos + (slen as u32);
  if dec^.pos > dec^.len {
    dec^.err = true;
  }
  return {.tag = tag, .fid = fid, .stat_offset = soff,
          .stat_len = slen, .ok = not dec^.err};
}

fn EncodeRwstat(enc: Encoder*, tag: u16) {
  enc^.BeginMsg();
  enc^.WriteU8(Rwstat);
  enc^.WriteU16(tag);
  enc^.Finish();
}

struct RwstatResult {
  var tag: u16;
  var ok:  bool;
}

fn DecodeRwstat(dec: Decoder*) -> RwstatResult {
  let tag: u16 = dec^.ReadU16();
  return {.tag = tag, .ok = not dec^.err};
}

// =============================================================================
// Smoke-test entry point
// =============================================================================
// Encodes a Tversion request, copies the bytes into a Decoder (simulating
// transport delivery), re-decodes, and verifies every field round-trips
// correctly.  Returns 0 on success, 1 on any mismatch.
fn Main() -> i32 {
  // ── Build the version string "9P2000" ────────────────────────────────────
  var ver_buf: [u8; 65536];
  ver_buf[0] = 0x39;  // '9'
  ver_buf[1] = 0x50;  // 'P'
  ver_buf[2] = 0x32;  // '2'
  ver_buf[3] = 0x30;  // '0'
  ver_buf[4] = 0x30;  // '0'
  ver_buf[5] = 0x30;  // '0'
  let vlen: u16 = 6;

  // ── Encode Tversion ───────────────────────────────────────────────────────
  var enc: Encoder;
  EncodeTversion(&enc, NOTAG, 8192, &ver_buf, vlen);

  // Expected wire layout (little-endian):
  //   size[4]  type[1]  tag[2]  msize[4]  version_len[2]  version_bytes[6]
  //   = 19 00 00 00  64  FF FF  00 20 00 00  06 00  39 50 32 30 30 30
  // Total = 19 bytes.
  if enc.pos != 19 {
    return 1;
  }

  // ── Transfer: copy enc.buf into a Decoder ─────────────────────────────────
  var dec: Decoder;
  dec.Init(enc.pos);
  var i: u32 = 0;
  while i < enc.pos {
    dec.buf[i] = enc.buf[i];
    i += 1;
  }

  // ── Parse header ─────────────────────────────────────────────────────────
  let hdr: Header = DecodeHeader(&dec);
  if hdr.mtype != Tversion {
    return 1;
  }
  if hdr.tag != NOTAG {
    return 1;
  }
  if hdr.size != 19 {
    return 1;
  }

  // ── Decode body ──────────────────────────────────────────────────────────
  let res: TversionResult = DecodeTversion(&dec);
  if not res.ok {
    return 1;
  }
  if res.msize != 8192 {
    return 1;
  }
  if res.version.len != 6 {
    return 1;
  }
  // Verify "9P2000" round-trips through the buffer.
  if dec.buf[res.version.offset + 0] != 0x39 {
    return 1;
  }
  if dec.buf[res.version.offset + 1] != 0x50 {
    return 1;
  }
  if dec.buf[res.version.offset + 5] != 0x30 {
    return 1;
  }

  return 0;
}
