// Copyright 2021 Oxide Computer Company

use crate::*;
use std::net::Ipv6Addr;

pub struct Buffer<'a> {
    pub data: &'a [u8],
    len: usize,
    offset: usize,
}

impl Buffer<'_> {
    pub fn new_from_slice(d: &[u8]) -> Buffer {
        Buffer {
            data: d,
            offset: 0,
            len: d.len(),
        }
    }

    fn check_size(&mut self, size: usize) -> Result<()> {
        if self.left() < size {
            Err(Error::TooShort)
        } else {
            Ok(())
        }
    }

    pub fn set_offset(&mut self, offset: usize) -> Result<()> {
        if offset > self.data.len() {
            Err(Error::TooShort)
        } else {
            self.offset = offset;
            Ok(())
        }
    }

    pub fn get_offset(&mut self) -> usize {
        self.offset
    }

    pub fn left(&mut self) -> usize {
        if self.offset < self.len {
            self.len - self.offset
        } else {
            0
        }
    }

    pub fn get_bytes(&mut self, bytes: usize) -> Result<Vec<u8>> {
        self.check_size(bytes)?;

        let mut v = Vec::new();
        v.extend_from_slice(&self.data[self.offset..self.offset + bytes]);
        self.offset += bytes;
        Ok(v)
    }

    pub fn get_32(&mut self) -> Result<u32> {
        self.check_size(4)?;
        let b = &self.data[self.offset..];
        self.offset += 4;

        Ok((b[0] as u32) << 24 | (b[1] as u32) << 16 | (b[2] as u32) << 8 | (b[3] as u32))
    }

    pub fn get_24(&mut self) -> Result<u32> {
        self.check_size(4)?;
        let b = &self.data[self.offset..];
        self.offset += 3;

        Ok((b[0] as u32) << 16 | (b[1] as u32) << 8 | (b[2] as u32))
    }

    pub fn get_16(&mut self) -> Result<u16> {
        self.check_size(2)?;
        let b = &self.data[self.offset..];
        self.offset += 2;

        Ok((b[0] as u16) << 8 | (b[1] as u16))
    }

    pub fn get_8(&mut self) -> Result<u8> {
        self.check_size(1)?;
        let b = self.data[self.offset];
        self.offset += 1;

        Ok(b)
    }

    pub fn get_ipv6addr(&mut self) -> Result<Ipv6Addr> {
        let x = self.get_bytes(16)?;
        let mut w = [0u16; 8];

        for i in 0..8 {
            w[i] = (x[2 * i] as u16) << 8 | (x[2 * i + 1] as u16);
        }

        Ok(Ipv6Addr::new(
            w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
        ))
    }
}

#[test]
fn test_byte() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = Buffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_8().unwrap(), 0x11);
    assert_eq!(tbuf.get_8().unwrap(), 0x22);
    assert_eq!(tbuf.get_8().unwrap(), 0x33);
    assert_eq!(tbuf.get_8().unwrap(), 0x44);
}

#[test]
fn test_short() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = Buffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_16().unwrap(), 0x1122);
    assert_eq!(tbuf.get_16().unwrap(), 0x3344);
}

#[test]
fn test_word() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = Buffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_32().unwrap(), 0x11223344);
}

#[test]
fn test_overflow() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = Buffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_32().unwrap(), 0x11223344);
    assert_eq!(tbuf.get_32(), Err(crate::Error::TooShort));
}
