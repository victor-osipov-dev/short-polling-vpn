//! Wire format: fixed-length frames packed into a batch.
//!
//! Frame: `session_id(16) | seq(4, BE) | flags(1) | length(4, BE) | payload`
//! Batch: `count(2, BE) | count * Frame`

use anyhow::{bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;

pub const FLAG_NEW: u8 = 0x01;
pub const FLAG_DATA: u8 = 0x02;
pub const FLAG_FIN: u8 = 0x04;
pub const FLAG_DNS: u8 = 0x08;
pub const FLAG_PAD: u8 = 0x10;

pub const SESSION_ID_LEN: usize = 16;
pub const HEADER_LEN: usize = SESSION_ID_LEN + 4 + 1 + 4;
pub const PROTO_VERSION: &str = "2";
pub const RESP_STREAM_MAGIC: [u8; 2] = [0x02, 0x00];

const PAD_TARGETS: [usize; 7] = [192, 256, 320, 384, 512, 640, 768];

#[derive(Clone, Debug)]
pub struct Frame {
    pub session_id: [u8; SESSION_ID_LEN],
    pub seq: u32,
    pub flags: u8,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(session_id: [u8; SESSION_ID_LEN], seq: u32, flags: u8, payload: Bytes) -> Self {
        Self {
            session_id,
            seq,
            flags,
            payload,
        }
    }

    pub fn new_target(session_id: [u8; SESSION_ID_LEN], seq: u32, host: &str, port: u16) -> Result<Self> {
        let host = host.as_bytes();
        if host.len() > 255 {
            bail!("host name is too long");
        }
        let mut payload = BytesMut::with_capacity(1 + host.len() + 2);
        payload.put_u8(host.len() as u8);
        payload.put_slice(host);
        payload.put_u16(port);
        Ok(Self::new(session_id, seq, FLAG_NEW, payload.freeze()))
    }

    pub fn parse_target(&self) -> Result<(String, u16)> {
        if self.payload.len() < 3 {
            bail!("truncated NEW frame");
        }
        let host_len = self.payload[0] as usize;
        if self.payload.len() < 1 + host_len + 2 {
            bail!("truncated NEW frame");
        }
        let host = std::str::from_utf8(&self.payload[1..1 + host_len])?.to_owned();
        let port = u16::from_be_bytes([self.payload[1 + host_len], self.payload[2 + host_len]]);
        Ok((host, port))
    }

    pub fn encode_into(&self, out: &mut BytesMut) {
        out.put_slice(&self.session_id);
        out.put_u32(self.seq);
        out.put_u8(self.flags);
        out.put_u32(self.payload.len() as u32);
        out.put_slice(&self.payload);
    }

    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        self.encode_into(&mut out);
        out.freeze()
    }

    pub fn decode(data: &[u8], offset: &mut usize) -> Result<Self> {
        if *offset + HEADER_LEN > data.len() {
            bail!("truncated frame header");
        }
        let mut sid = [0u8; SESSION_ID_LEN];
        sid.copy_from_slice(&data[*offset..*offset + SESSION_ID_LEN]);
        let seq = u32::from_be_bytes(
            data[*offset + 16..*offset + 20]
                .try_into()
                .expect("4 bytes"),
        );
        let flags = data[*offset + 20];
        let len = u32::from_be_bytes(
            data[*offset + 21..*offset + 25]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        *offset += HEADER_LEN;
        if *offset + len > data.len() {
            bail!("truncated frame payload");
        }
        let payload = Bytes::copy_from_slice(&data[*offset..*offset + len]);
        *offset += len;
        Ok(Self::new(sid, seq, flags, payload))
    }
}

pub fn pack_frames(frames: &[Frame]) -> Bytes {
    let size = 2 + frames.iter().map(|f| HEADER_LEN + f.payload.len()).sum::<usize>();
    let mut out = BytesMut::with_capacity(size);
    out.put_u16(frames.len() as u16);
    for f in frames {
        f.encode_into(&mut out);
    }
    out.freeze()
}

pub fn unpack_frames(data: &[u8]) -> Result<Vec<Frame>> {
    if data.len() < 2 {
        return Ok(Vec::new());
    }
    let count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let mut frames = Vec::with_capacity(count);
    for _ in 0..count {
        frames.push(Frame::decode(data, &mut offset)?);
    }
    Ok(frames)
}

/// Adds a padding frame so short/empty polls do not leak their real size.
pub fn pad_frames(mut frames: Vec<Frame>) -> Vec<Frame> {
    let base = 2 + frames.iter().map(|f| HEADER_LEN + f.payload.len()).sum::<usize>();
    let mut rng = rand::thread_rng();
    let target = if frames.is_empty() {
        PAD_TARGETS[rng.gen_range(0..PAD_TARGETS.len())]
    } else {
        base + rng.gen_range(64..=256)
    };
    if target <= base + HEADER_LEN {
        return frames;
    }
    let need = target - base - HEADER_LEN;
    let mut payload = vec![0u8; need];
    rng.fill(&mut payload[..]);
    frames.push(Frame::new(random_sid(), 0, FLAG_PAD, Bytes::from(payload)));
    frames
}

pub fn random_sid() -> [u8; SESSION_ID_LEN] {
    let mut sid = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill(&mut sid);
    sid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let sid = [7u8; 16];
        let f = Frame::new_target(sid, 1, "example.com", 443).unwrap();
        let packed = pack_frames(&[f.clone()]);
        let out = unpack_frames(&packed).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].session_id, sid);
        assert_eq!(out[0].flags, FLAG_NEW);
        assert_eq!(out[0].parse_target().unwrap(), ("example.com".to_owned(), 443));
    }

    #[test]
    fn header_is_25_bytes() {
        assert_eq!(HEADER_LEN, 25);
        let sid = [0xab; 16];
        let f = Frame::new(sid, 0x01020304, FLAG_DATA, Bytes::from_static(b"hi"));
        let enc = f.encode();
        assert_eq!(&enc[..16], &sid);
        assert_eq!(&enc[16..20], &[1, 2, 3, 4]);
        assert_eq!(enc[20], FLAG_DATA);
        assert_eq!(&enc[21..25], &[0, 0, 0, 2]);
        assert_eq!(&enc[25..], b"hi");
    }

    #[test]
    fn pads_empty_poll() {
        let packed = pack_frames(&pad_frames(Vec::new()));
        assert!(packed.len() >= 192);
        let frames = unpack_frames(&packed).unwrap();
        assert_eq!(frames[0].flags, FLAG_PAD);
    }

    #[test]
    fn rejects_truncated() {
        assert!(unpack_frames(&[0, 1, 0]).is_err());
    }
}
