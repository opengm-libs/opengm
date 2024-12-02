use std::io;

use crate::{consts::VERSION_TLCP, messages::Alert, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RecordType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Site2Site = 80, // TLCP: SSL VPN site2site
    #[default]
    None = 0,
}

impl From<u8> for RecordType {
    fn from(v: u8) -> Self {
        match v {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            80 => Self::Site2Site,
            _ => Self::None,
        }
    }
}

impl From<RecordType> for u8 {
    fn from(value: RecordType) -> Self {
        value as u8
    }
}

impl RecordType {
    pub fn max_payload_size_for_write(self) -> usize {
        match self {
            // TODO
            RecordType::ChangeCipherSpec => 1024,
            RecordType::Alert => 1024,
            RecordType::Handshake => 1024,
            RecordType::ApplicationData => 1024,
            RecordType::Site2Site => 1024,
            RecordType::None => 0,
        }
    }
}

const IV_SIZE: usize = 16;

#[derive(Debug)]
pub struct Record {
    pub typ: RecordType,
    pub vers: u16,

    // fragment = [0;fragment_start] || real-fragment
    fragment: Vec<u8>,
    fragment_start: usize,
}

impl Default for Record {
    fn default() -> Self {
        Record {
            typ: RecordType::None,
            vers: VERSION_TLCP,
            fragment: Vec::with_capacity(RECORD_INIT_SIZE),
            fragment_start: 0,
        }
    }
}

impl Record {
    pub fn new(typ: RecordType, vers: u16, pool: &mut RecordPool) -> Record {
        let mut r = pool.get();
        r.set_type_vers(typ, vers);
        r
    }

    #[inline]
    pub fn drop(self, pool: &mut RecordPool) {
        pool.put(self)
    }

    #[inline]
    pub fn reset(&mut self) {
        self.typ = RecordType::None;
        self.vers = VERSION_TLCP;
        self.fragment.clear();
        self.fragment_start = 0;
    }

    #[inline]
    pub fn typ(&self) -> RecordType {
        self.typ
    }

    #[inline]
    pub fn vers(&self) -> u16 {
        self.vers
    }

    // length returns Record.length
    #[inline]
    pub fn length(&self) -> u16 {
        (self.fragment.len() - self.fragment_start) as u16
    }

    #[inline]
    pub fn make_header(typ: RecordType, vers: u16, length: u16) -> [u8; 5] {
        [u8::from(typ), (vers >> 8) as u8, vers as u8, (length >> 8) as u8, length as u8]
    }

    #[inline]
    pub fn parse_header(header: &[u8]) -> (RecordType, u16, u16) {
        (header[0].into(), ((header[1] as u16) << 8) + header[2] as u16, ((header[3] as u16) << 8) + header[4] as u16)
    }

    #[inline]
    pub fn header(&self) -> [u8; 5] {
        Record::make_header(self.typ, self.vers, self.length())
    }

    #[inline]
    pub fn set_type_vers(&mut self, typ: RecordType, vers: u16) {
        self.typ = typ;
        self.vers = vers;
    }

    #[inline]
    pub(crate) fn fragment_shift_left(&mut self, n: usize) {
        self.fragment_start += n;
    }

    #[inline]
    pub(crate) fn fragment_shift_right(&mut self, n: usize) {
        self.fragment_start -= n;
    }

    #[inline]
    pub fn fragment_resize(&mut self, new_len: usize, value: u8) {
        self.fragment.resize(self.fragment_start + new_len, value);
    }

    #[inline]
    pub fn fragment_set(&mut self, fragment: &[u8]) {
        self.fragment.clear();
        self.fragment_start = 0;
        self.fragment.extend_from_slice(fragment);
    }

    #[inline]
    pub fn fragment_push(&mut self, data: u8) {
        self.fragment.push(data);
    }

    #[inline]
    pub fn fragment_append(&mut self, fragment: &[u8]) {
        self.fragment.extend_from_slice(fragment);
    }

    #[inline]
    pub fn fragment_as_ref(&self) -> &[u8] {
        &self.fragment[self.fragment_start..]
    }

    #[inline]
    pub fn fragment_as_mut(&mut self) -> &mut [u8] {
        &mut self.fragment[self.fragment_start..]
    }

    #[inline]
    pub fn fragment_split_at_mut(&mut self, mid: usize) -> (&mut [u8], &mut [u8]) {
        self.fragment_as_mut().split_at_mut(mid)
    }

    #[inline]
    pub fn fragment_split_at(&self, mid: usize) -> (&[u8], &[u8]) {
        self.fragment_as_ref().split_at(mid)
    }

    #[inline]
    pub fn read_alert(&self) -> Option<Alert> {
        if self.typ() != RecordType::Alert || self.length() != 2 {
            return None;
        }

        // omit the alert level.
        Alert::try_from(self.fragment_as_ref()[1]).ok()
    }

    // return the full bytes slices of Record
    #[inline]
    pub fn as_slices(&self) -> ([u8; 5], &[u8]) {
        (self.header(), self.fragment_as_ref())
    }

    // returns the owned bytes of the record.
    #[inline]
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(5 + self.fragment.len() as usize);
        b.extend_from_slice(&self.header());
        b.extend_from_slice(&self.fragment_as_ref());
        b
    }

    #[inline]
    pub fn read(&mut self, r: &mut impl io::Read) -> Result<()> {
        let mut header = [0u8; 5];

        r.read_exact(&mut header)?;
        let (typ, vers, length) = Record::parse_header(&header);
        if typ == RecordType::None {
            return Err(Alert::UnexpectedMessage.into());
        }
        if length > MAX_RECORD_LENGTH as u16 {
            return Err(Alert::RecordOverflow.into());
        }
        self.set_type_vers(typ, vers);
        self.fragment_start = 0;
        self.fragment.resize(length as usize, 0);
        r.read_exact(&mut self.fragment)?;
        Ok(())
    }

    #[inline]
    pub fn write(&self, w: &mut impl io::Write) -> Result<usize> {
        let mut n = w.write(&self.header())?;
        n += w.write(self.fragment_as_ref())?;
        w.flush()?;
        Ok(n)
    }
}

const RECORD_INIT_SIZE: usize = 2048;
const RECORD_POOL_SIZE: usize = 8;
const RECORD_HEADER_LENGTH: usize = 5;
// TODO
const MAX_RECORD_LENGTH: usize = 4096;

#[derive(Debug, Default)]
pub(crate) struct RecordPool {
    pub pool: Vec<Record>,
}

impl RecordPool {
    pub fn new() -> RecordPool {
        RecordPool { pool: Vec::new() }
    }

    #[inline]
    pub fn put(&mut self, r: Record) {
        if self.pool.len() < RECORD_POOL_SIZE {
            self.pool.push(r);
        }
    }
    #[inline]
    pub fn get(&mut self) -> Record {
        if let Some(r) = self.pool.pop() {
            r
        } else {
            Record::default()
        }
    }
    #[inline]
    pub fn size(&self) -> usize {
        self.pool.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_record_type() {
        println!("{:?}", RecordType::ApplicationData);
    }
}
