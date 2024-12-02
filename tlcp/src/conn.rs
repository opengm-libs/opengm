use cipher_suits::CipherSuite;
use config::Config;
use consts::*;
use handshake_client::{
    make_client_hello, precess_server_hello, ClientHandshakeState,
};
use handshake_server::{
    make_server_hello, precess_client_hello, ServerHandshakeState,
};
use messages::*;
use opengm_crypto::sm3;
use opengm_crypto::sm3::Digest;
use rand::{Rng, RngCore};
use record::RecordPool;
use traits::{TlcpAead, TlcpEnc, TlcpMac};
use utils::check_padding;

use crate::record::Record;
use crate::*;
use crate::{consts::VERSION_TLCP, record::RecordType};

use std::cell::RefCell;
use std::rc::Rc;
use std::{
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
};

macro_rules! mac {
    ($mac: expr, $out: expr,  $($data:expr),+ $(,)?) => {{
        $mac.reset();
        $(
            $mac.write($data);
        )*
        $mac.sum_into($out);
    }};
}

pub struct Conn<C: io::Write + io::Read> {
    pub(crate)conn: C,

    pub(crate) config: Config,
    pub(crate) is_client: bool,

    pub(crate)vers: u16, // version, TLCP = 1.1

    // cipher_suit_id: u16,
    // cipher_suit: Option<CipherSuite>, // negotiated cipher suite
    pub(crate) read_seq_num: u64,
    pub(crate) write_seq_num: u64,

    pub(crate) input: HalfConn,
    pub(crate) output: HalfConn,

    pub(crate)buf: Vec<u8>,

    //assume the Conn is running in a single thread.
    pub(crate) rng: Rc<RefCell<Box<dyn RngCore>>>,
    // rng: Arc<Box<dyn RngCore>>,
    pub(crate) record_pool: RecordPool,
}

// write/read
pub struct HalfConn {
    buf: Vec<u8>,
    is_read: bool,

    is_aead: bool,
    mac: Option<Box<dyn TlcpMac>>,
    enc: Option<Box<dyn TlcpEnc>>,
    aead: Option<Box<dyn TlcpAead>>,

    next_is_aead: bool,
    next_mac: Option<Box<dyn TlcpMac>>,
    next_enc: Option<Box<dyn TlcpEnc>>,
    next_aead: Option<Box<dyn TlcpAead>>,

    rng: Rc<RefCell<Box<dyn RngCore>>>,
}

impl HalfConn {
    pub fn default(is_read: bool, rng: Rc<RefCell<Box<dyn RngCore>>>) -> Self {
        Self {
            buf: Vec::new(),
            is_read: is_read,
            is_aead: false,
            mac: None,
            enc: None,
            aead: None,

            next_mac: None,
            next_enc: None,
            next_is_aead: false,
            next_aead: None,
            rng,
        }
    }

    // fn new(cipher_suit: &CipherSuite, key_block: &KeyBlock,rng: RefCell<Box<dyn RngCore>>, is_client: bool, is_read: bool) -> Self {
    //     if cipher_suit.is_aead() {
    //         todo!()
    //     } else {
    //         let (enc_key, mac_key, iv) = match (is_client, is_read) {
    //             // client read/server write
    //             (true, true) | (false, false) => (key_block.server_write_key.as_slice(), key_block.server_write_mac_key.as_slice(), key_block.server_write_IV.as_slice()),

    //             // client write/server read
    //             (true, false) | (false, true) => (key_block.client_write_key.as_slice(), key_block.client_write_mac_key.as_slice(), key_block.client_write_IV.as_slice()),
    //         };
    //         HalfConn {
    //             buf: Vec::new(),
    //             is_read: is_read,
    //             mac: (cipher_suit.mac)(mac_key),
    //             enc: (cipher_suit.enc)(enc_key, is_read),
    //             aead: (cipher_suit.aead)(enc_key, iv),
    //             is_aead: false,
    //             next_is_aead: false,
    //             next_mac: None,
    //             next_enc: None,
    //             next_aead: None,
    //             rng: rng,
    //         }
    //     }
    // }

    #[inline]
    pub fn read_crypt(
        &mut self,
        seq_num: u64,
        record: &mut Record,
    ) -> Result<()> {
        // decrypt
        if self.is_aead {
            self.read_crypt_aead(seq_num, record)
        } else {
            self.read_crypt_mac_then_enc(seq_num, record)
        }
    }

    pub fn read_crypt_aead(
        &mut self,
        seq_num: u64,
        record: &mut Record,
    ) -> Result<()> {
        if self.aead.is_none() {
            return Ok(());
        }
        let aead = self.aead.as_mut().unwrap();
        let typ = record.typ();
        let vers = record.vers();
        let explicite_nonce_length = aead.explicit_nonce_size();
        let tag_length = aead.overhead();

        let payload = record.fragment_as_mut();
        if payload.len() < explicite_nonce_length + tag_length {
            return Err(Alert::DecryptError.into());
        }
        let data_length = payload.len() - (explicite_nonce_length + tag_length);

        let (explicite_nonce, ciphertext) =
            payload.split_at_mut(explicite_nonce_length);
        let mut add = [0; 13];
        add[..8].copy_from_slice(&seq_num.to_be_bytes());
        add[8] = u8::from(typ);
        add[9] = (vers >> 8) as u8;
        add[10] = vers as u8;
        add[11] = (data_length >> 8) as u8;
        add[12] = data_length as u8;

        let ciphertext_length = ciphertext.len() - tag_length;
        let (ciphertext, tag) = ciphertext.split_at_mut(ciphertext_length);

        aead.open(ciphertext, tag, &explicite_nonce, &add)?;
        record.fragment_shift_left(explicite_nonce_length);
        record.fragment_resize(ciphertext_length, 0);
        Ok(())
    }

    //
    pub fn read_crypt_mac_then_enc(
        &mut self,
        seq_num: u64,
        record: &mut Record,
    ) -> Result<()> {
        if self.enc.is_none() || self.mac.is_none() {
            return Ok(());
        }

        let enc = self.enc.as_ref().unwrap();
        let mac = self.mac.as_mut().unwrap();
        let typ = record.typ();
        let vers = record.vers();

        let block_size = enc.block_size();
        let mac_size = mac.mac_size();

        let payload = record.fragment_as_mut();
        if payload.len() <= block_size + mac_size
            || payload.len() % block_size != 0
        {
            return Err(Alert::DecryptError.into());
        }

        let (iv, plaintext) = payload.split_at_mut(block_size);
        enc.crypt_blocks(iv, plaintext)?;

        // plaintext length
        let padding_length = plaintext[plaintext.len() - 1] as isize;
        let data_length =
            plaintext.len() as isize - (padding_length + 1) - mac_size as isize;
        // we may not alow a empty record body.
        if data_length <= 0 {
            return Err(Alert::DecryptError.into());
        }

        let (data, tail) = plaintext.split_at(data_length as usize);
        let (mac_value, paddings) = tail.split_at(mac_size);

        // check padding
        if !check_padding(&paddings) {
            return Err(Alert::DecryptError.into());
        }

        // check mac
        let mut computed_mac_value = [0; 32];
        debug_assert!(mac_size <= 32);
        mac!(
            mac,
            &mut computed_mac_value,
            &seq_num.to_be_bytes(),
            &[
                u8::from(typ),
                (vers >> 8) as u8,
                vers as u8,
                (data_length >> 8) as u8,
                data_length as u8
            ],
            data
        );

        if !mac_value.eq(&computed_mac_value[..mac_size]) {
            return Err(Alert::BadRecordMAC.into());
        }

        // adjust record body
        record.fragment_shift_left(block_size); // data||iv
        record.fragment_resize(data_length as usize, 0); //data
        Ok(())
    }

    #[inline]
    pub fn write_crypt(
        &mut self,
        out: &mut Record,
        seq_num: u64,
        typ: RecordType,
        vers: u16,
        data: &[u8],
    ) -> Result<()> {
        // encrypt
        if self.is_aead {
            self.write_crypt_aead(out, seq_num, typ, vers, data)
        } else {
            self.write_crypt_mac_then_enc(out, seq_num, typ, vers, data)
        }
    }
    pub fn write_crypt_aead(
        &mut self,
        out: &mut Record,
        seq_num: u64,
        typ: RecordType,
        vers: u16,
        data: &[u8],
    ) -> Result<()> {
        if self.aead.is_none() {
            return Ok(());
        }
        let aead = self.aead.as_mut().unwrap();
        out.reset();
        out.set_type_vers(typ, vers);
        let explicite_nonce_length = aead.explicit_nonce_size();
        let tag_length = aead.overhead();
        let data_length = data.len();

        out.fragment_resize(
            explicite_nonce_length + data_length + tag_length,
            0,
        );
        let (explicite_nonce, tail) =
            out.fragment_split_at_mut(explicite_nonce_length);
        let (ciphertext, tag) = tail.split_at_mut(data_length);

        // use seq num as the explicite nonce is ok.
        explicite_nonce.copy_from_slice(&seq_num.to_be_bytes());
        // self.rng.borrow_mut().try_fill_bytes(explicite_nonce)?;

        ciphertext.copy_from_slice(data);
        let mut add = [0; 13];
        add[..8].copy_from_slice(&seq_num.to_be_bytes());
        add[8] = u8::from(typ);
        add[9] = (vers >> 8) as u8;
        add[10] = vers as u8;
        add[11] = (data_length >> 8) as u8;
        add[12] = data_length as u8;

        aead.seal(ciphertext, tag, explicite_nonce, &add)?;
        Ok(())
    }
    pub fn write_crypt_mac_then_enc(
        &mut self,
        out: &mut Record,
        seq_num: u64,
        typ: RecordType,
        vers: u16,
        data: &[u8],
    ) -> Result<()> {
        // encrypt
        out.set_type_vers(typ, vers);

        if self.enc.is_none() || self.mac.is_none() {
            out.fragment_set(data);
            return Ok(());
        }

        let enc = self.enc.as_ref().unwrap();
        let mac = self.mac.as_mut().unwrap();

        let block_size = enc.block_size();
        let mac_size = mac.mac_size();
        let data_length = data.len();

        // iv || data || mac (|| padding)
        out.fragment_resize(block_size + data_length + mac_size, 0);
        let (out_iv, tail) = out.fragment_split_at_mut(block_size);
        let (out_data, out_mac) = tail.split_at_mut(data_length);

        self.rng.borrow_mut().try_fill_bytes(out_iv)?;
        out_data.copy_from_slice(data);

        mac!(
            mac,
            out_mac,
            &seq_num.to_be_bytes(),
            &Record::make_header(typ, vers, data_length as u16),
            out_data,
        );

        // Now out.fragment = iv || data || mac

        // padding
        let padding_length = block_size - (data.len() % block_size);
        let new_length = out.length() as usize + padding_length;
        out.fragment_resize(new_length, (padding_length - 1) as u8);

        // Now out.fragment = iv || data || mac || padding

        // encrypt
        let (iv, plaintext) = out.fragment_split_at_mut(block_size);
        enc.crypt_blocks(iv, plaintext)?;

        Ok(())
    }

    pub fn prepare_cipher_spec(
        &mut self,
        cipher_suit: &CipherSuite,
        mac_key: &[u8],
        enc_key: &[u8],
        iv: &[u8],
    ) {
        self.next_mac = (cipher_suit.mac)(mac_key);
        self.next_enc = (cipher_suit.enc)(enc_key, self.is_read);
        self.next_aead = (cipher_suit.aead)(enc_key, iv, self.is_read);
        self.next_is_aead = cipher_suit.is_aead();
    }

    pub fn change_cipher_spec(&mut self) -> Result<()> {
        if self.next_enc.is_none() && self.next_aead.is_none() {
            return Err(Error::InternalError);
        }
        self.enc = self.next_enc.take();
        self.mac = self.next_mac.take();
        self.aead = self.next_aead.take();
        self.is_aead = self.next_is_aead;
        self.next_is_aead = false;
        Ok(())
    }
}

impl Conn<TcpStream> {
    pub fn connect<A: ToSocketAddrs>(
        addr: A,
        config: &Config,
    ) -> Result<Conn<TcpStream>> {
        let stream = TcpStream::connect(addr).unwrap();
        // should clone from config
        // let rng = Rc::new(RefCell::new(Box::new(thread_rng())));

        Ok(Conn {
            conn: stream,
            config: Config::default(),
            vers: VERSION_TLCP,
            read_seq_num: 0,
            write_seq_num: 0,

            input: HalfConn::default(true, config.rng.clone()),
            output: HalfConn::default(false, config.rng.clone()),

            is_client: true,
            record_pool: RecordPool::new(),
            buf: Vec::new(),

            rng: config.rng.clone(),
        })
    }
}

impl<C: io::Write + io::Read> Read for Conn<C> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.conn.read(buf)
    }
}

impl<C: io::Write + io::Read> Write for Conn<C> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.conn.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.conn.flush()
    }
}

const RECORD_HEADER_LENGTH: usize = 5;

impl<C: io::Write + io::Read> Conn<C> {
    // writeRecordLocked writes a TLS record with the given type and payload to the
    // connection and updates the record layer state.
    pub fn write_record(
        &mut self,
        typ: RecordType,
        data: &[u8],
    ) -> Result<usize> {
        let mut n = 0;
        let mut data = data;
        let mut record = Record::new(typ, self.vers, &mut self.record_pool);
        while data.len() > 0 {
            let mut m = data.len();
            let max_payload = typ.max_payload_size_for_write();
            if m > max_payload {
                m = max_payload;
            }

            // fix: unnessary memcpy
            self.output.write_crypt(
                &mut record,
                self.write_seq_num,
                typ,
                self.vers,
                data,
            )?;

            record.write(self)?;
            self.write_seq_num += 1;
            n += m;
            data = &data[m..];
        }
        record.drop(&mut self.record_pool);
        Ok(n)
    }

    // read a record append to buf.
    pub fn read_record(&mut self, record: &mut Record) -> Result<()> {
        // let mut record = self.record_pool.get();
        record.read(self)?;

        // decrypt
        self.input.read_crypt(self.read_seq_num, record)?;
        self.read_seq_num += 1;

        match record.read_alert() {
            Some(a) => Err(Error::from(a)),
            _ => Ok(()),
        }
    }

    pub fn write_alert(&mut self, a: Alert) -> Result<usize> {
        self.write_record(RecordType::Alert, &[a.level() as u8, a as u8])
    }

    pub fn write_change_cipher_spec(&mut self) -> Result<usize> {
        let res = self.write_record(
            RecordType::ChangeCipherSpec,
            &ChangeCipherSpecMsg::new().bytes(),
        )?;
        self.write_seq_num = 0;
        self.output.change_cipher_spec()?;
        Ok(res)
    }

    pub fn read_change_cipher_spec(&mut self) -> Result<()> {
        let mut record = self.record_pool.get();
        self.read_record(&mut record)?;
        if record.typ() != RecordType::ChangeCipherSpec
            || ChangeCipherSpecMsg::try_from(record.fragment_as_ref()).is_none()
        {
            return Err(Alert::UnexpectedMessage.into());
        }
        self.read_seq_num = 0;
        record.drop(&mut self.record_pool);
        Ok(())
    }

    // plain -> compressed
    pub fn compress(&mut self, _record: &mut Record) {}

    pub fn handshake(&mut self) -> Result<()> {
        if self.is_client {
            self.handshake_client()
        } else {
            self.handshake_server()
        }
    }

    pub fn handshake_client(&mut self) -> Result<()> {
        let mut client_hello_msg = make_client_hello(&self.config);
        println!(
            "ClientHello: {:?}",
            self.write_record(RecordType::Handshake, client_hello_msg.bytes()?)
        );

        let mut record = self.record_pool.get();

        self.read_record(&mut record)?;
        let server_hello_msg =
            ServerHelloMsgBorrowed::parse(record.fragment_as_ref())
                .ok_or(Error::UnexpectedMessage)?;
        println!("ServerHello: {:?}", server_hello_msg);

        // check server's version and cipher suite
        let (version, cipher_suite_id) =
            precess_server_hello(&client_hello_msg, &server_hello_msg)?;
        let cipher_suit = CipherSuite::try_from(cipher_suite_id)?;

        ClientHandshakeState::<C, sm3::Digest, 32>::new(
            self,
            client_hello_msg,
            server_hello_msg,
            version,
            cipher_suit,
        )
        .handshake()?;

        self.record_pool.put(record);
        Ok(())
    }

    pub fn handshake_server(&mut self) -> Result<()> {
        let mut record = self.record_pool.get();

        self.read_record(&mut record)?;
        let client_hello_msg =
            ClientHelloMsgBorrowed::parse(record.fragment_as_ref())
                .ok_or(Error::UnexpectedMessage)?;
        println!("client_hello.");

        // process client_hello_msg. choose version and cipher_suite.
        let (vers, cipher_suits_id) =
            precess_client_hello(&client_hello_msg, &self.config)?;
        let mut server_hello_msg =
            make_server_hello(vers, cipher_suits_id, &self.config);
        let cipher_suit = CipherSuite::try_from(cipher_suits_id)?;

        ServerHandshakeState::<C, sm3::Digest, 32>::new(
            self,
            client_hello_msg,
            server_hello_msg,
            vers,
            cipher_suit,
        )
        .handshake()?;

        self.record_pool.put(record);
        Ok(())
    }
}

fn write_finished_hash(hash: &mut Digest, data: &[u8]) {
    println!("finished hash write: {}", data.len());
    hash.write(data);
}
