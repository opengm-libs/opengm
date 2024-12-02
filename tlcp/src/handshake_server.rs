use std::io;

use rand::*;

use crate::crypto_engine::CryptoEngine;
use crate::key_agreement::ServerKeyAgreement;
use crate::prf::{
    compute_finished_verify_data, compute_master_secret, KeyBlock,
};
use crate::record::RecordType;
use crate::traits::Hash;
use crate::{
    cipher_suits::CipherSuite, config::Config, conn::Conn,
    consts::COMPRESSION_NONE, finished_hash::FinishedHash, messages::*,
    record::Record,
};
use crate::{Error, Result};

// find the first element in a1 that also in a2.
fn mutual<T: Copy + PartialEq>(a1: &[T], a2: &[T]) -> Option<T> {
    for i in a1 {
        for j in a2 {
            if *i == *j {
                return Some(*i);
            }
        }
    }
    None
}

// precess ServerHelloMsg and returns the neociated (version, cipher_suite_id)
pub fn precess_client_hello(
    client_hello: &ClientHelloMsgBorrowed,
    config: &Config,
) -> Result<(u16, u16)> {
    let supported_versions = config.supported_versions();
    let supported_cipher_suites_id = config.supported_cipher_suites();

    let vers = mutual(&[client_hello.vers], supported_versions)
        .ok_or(Alert::ProtocolVersion)?;
    let cipher_suites =
        mutual(supported_cipher_suites_id, &client_hello.cipher_suite_ids)
            .ok_or(Alert::HandshakeFailure)?;

    if client_hello.compression_methods.contains(&COMPRESSION_NONE) {
        return Ok((vers, cipher_suites));
    }
    Err(Alert::HandshakeFailure.into())
}

pub(crate) fn make_server_hello(
    vers: u16,
    cipher_suite_id: u16,
    config: &Config,
) -> ServerHelloMsgOwned {
    ServerHelloMsgOwned {
        raw: None,
        vers: vers,
        random: config.rng.borrow_mut().gen(),
        session_id: Vec::new(),
        cipher_suite_id,
        compression_method: COMPRESSION_NONE,
    }
}

// ClientHandshakeState do the handshake work after receiving server's hello.
pub struct ServerHandshakeState<
    'a,
    C: io::Write + io::Read,
    H: Hash<DIGEST_SIZE> + Default,
    const DIGEST_SIZE: usize,
> {
    pub conn: &'a mut Conn<C>,
    client_hello: ClientHelloMsgBorrowed<'a>,
    server_hello: ServerHelloMsgOwned,
    vers: u16,
    suite: CipherSuite,

    finishedHash: FinishedHash<H, DIGEST_SIZE>,
    masterSecret: Option<[u8; 48]>,
    // session      *ClientSessionSta

    // record buffer
    certificate_record: Record,
    server_key_exchange_record: Record,
    server_hello_done_record: Record,
    client_key_exchange_record: Record,
    client_finished_record: Record,
}

impl<
        'a,
        C: io::Write + io::Read,
        H: Hash<DIGEST_SIZE> + Default,
        const DIGEST_SIZE: usize,
    > ServerHandshakeState<'a, C, H, DIGEST_SIZE>
{
    pub fn new(
        conn: &'a mut Conn<C>,
        client_hello: ClientHelloMsgBorrowed<'a>,
        server_hello: ServerHelloMsgOwned,
        vers: u16,
        cipher_suit: CipherSuite,
    ) -> Self {
        let certificate_record = conn.record_pool.get();
        let server_key_exchange_record = conn.record_pool.get();
        let server_hello_done_record = conn.record_pool.get();
        let client_key_exchange = conn.record_pool.get();
        let client_finished_record = conn.record_pool.get();
        ServerHandshakeState {
            conn,
            server_hello,
            client_hello,
            vers,
            suite: cipher_suit,
            finishedHash: FinishedHash::new(),
            masterSecret: None,
            certificate_record,
            server_key_exchange_record,
            server_hello_done_record,
            client_key_exchange_record: client_key_exchange,
            client_finished_record,
        }
    }

    pub fn handshake(&mut self) -> Result<()> {
        let conn = &mut *self.conn;

        self.finishedHash.write(self.client_hello.bytes()?);
        self.finishedHash.write(self.server_hello.bytes()?);
        print!("serverHello.");

        // ServerHello
        conn.write_record(RecordType::Handshake, self.server_hello.bytes()?)?;

        // // Certificate

        let mut certificate_msg = CertificateMsgOwned {
            raw: None,
            certificates: conn
                .config
                .crypto
                .as_ref()
                .unwrap()
                .certificates()
                .clone(),
        };
        self.finishedHash.write(certificate_msg.bytes()?);
        conn.write_record(RecordType::Handshake, certificate_msg.bytes()?)?;

        // ServerKeyExchange
        let mut server_key_exchange_msg = conn
            .config
            .crypto
            .as_ref()
            .unwrap()
            .generate_server_key_exchange(
                self.server_hello.cipher_suite_id,
                &self.client_hello,
                &self.server_hello,
            );
        self.finishedHash.write(server_key_exchange_msg.bytes()?);
        conn.write_record(
            RecordType::Handshake,
            server_key_exchange_msg.bytes()?,
        )?;

        // CertificateRequest
        // omit

        // ServerHelloDone
        self.finishedHash
            .write(ServerHelloDoneMsg::default().bytes());
        conn.write_record(
            RecordType::Handshake,
            ServerHelloDoneMsg::default().bytes(),
        )?;

        // ClientKeyExchange
        let client_key_exchange_record = &mut self.client_key_exchange_record;
        conn.read_record(client_key_exchange_record)?;
        let client_key_exchange_msg = ClientKeyExchangeMsgBorrowed::parse(
            client_key_exchange_record.fragment_as_ref(),
        )
        .ok_or(Error::from(Alert::UnexpectedMessage))?;
        self.finishedHash.write(client_key_exchange_msg.bytes()?);

        let pre_master_secret = conn
            .config
            .crypto
            .as_ref()
            .unwrap()
            .process_client_key_exchange(self.vers, &client_key_exchange_msg)?;
        println!(
            "client_key_exchange_msg, pre_master_secret = {:?}",
            pre_master_secret
        );

        // 派生密钥.
        let master_secret = compute_master_secret(
            &pre_master_secret,
            &self.client_hello.random,
            &self.server_hello.random,
        );
        let cipher_suit = &self.suite;
        let key_block = KeyBlock::new(
            &master_secret,
            &self.client_hello.random,
            &self.server_hello.random,
            cipher_suit.mac_len,
            cipher_suit.key_len,
            cipher_suit.iv_len,
        );
        conn.output.prepare_cipher_spec(
            cipher_suit,
            &key_block.server_write_mac_key,
            &key_block.server_write_key,
            &key_block.server_write_IV,
        );
        conn.input.prepare_cipher_spec(
            cipher_suit,
            &key_block.client_write_mac_key,
            &key_block.client_write_key,
            &key_block.client_write_IV,
        );

        // client [change_cipher_spec]
        conn.read_change_cipher_spec()?;
        // server [change_cipher_spec]
        conn.input.change_cipher_spec()?;

        // Client Finished
        let client_finished_record = &mut self.client_finished_record;
        conn.read_record(client_finished_record)?;
        let client_finished = FinishedMsgBorrowed::parse(
            client_finished_record.fragment_as_ref(),
        )
        .ok_or(Error::from(Alert::UnexpectedMessage))?;
        let hash = self.finishedHash.sum();
        // server computed client finished data
        let client_finished_should_be =
            compute_finished_verify_data(&master_secret, &hash, true);
        if client_finished.verify_data != client_finished_should_be {
            return Err(Error::from(Alert::HandshakeFailure));
        }
        self.finishedHash.write(client_finished.bytes());

        conn.write_change_cipher_spec()?;

        // send server Finished
        let hash = self.finishedHash.sum();
        let finished_data =
            compute_finished_verify_data(&master_secret, &hash, false);
        let mut finished_msg = FinishedMsgOwned::new(&finished_data);
        println!(
            "server Finished: {:?}",
            conn.write_record(RecordType::Handshake, finished_msg.bytes()?)?
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::*;

    use crate::config::Config;
    use crate::consts::VERSION_TLCP;
    use crate::crypto_engine::SM2Engine;
    use opengm_crypto::cryptobyte::asn1::BitString;
    use opengm_crypto::cryptobyte::Builder;
    use crate::Result;
    use crate::{conn::*, record::*};
    use std::cell::RefCell;
    use std::net::TcpListener;
    use std::rc::Rc;

    #[test]
    fn test_server() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
        // accept connections and process them serially
        for stream in listener.incoming() {
            handle_client(stream?);
        }
        Ok(())
    }

    fn handle_client(stream: std::net::TcpStream) {
        println!("connected");

        let mut config = Config::default();
        config.crypto = Some(Box::new(SM2Engine::new(Box::new(thread_rng()))));
        let rng: Rc<RefCell<Box<dyn RngCore>>> =
            Rc::new(RefCell::new(Box::new(thread_rng())));
        let mut conn = Conn {
            conn: stream,
            config: config,
            vers: VERSION_TLCP,
            read_seq_num: 0,
            write_seq_num: 0,

            input: HalfConn::default(true, rng.clone()),
            output: HalfConn::default(false, rng.clone()),

            is_client: false,
            record_pool: RecordPool::new(),
            buf: Vec::new(),

            rng: Rc::new(RefCell::new(Box::new(thread_rng()))),
        };

        conn.handshake().unwrap();

        let mut record = conn.record_pool.get();
        loop {
            match conn.read_record(&mut record) {
                Ok(()) => {
                    print!("{:x?}", record.bytes());
                    print!(
                        "received: {}\n\n",
                        String::from_utf8(record.fragment_as_ref().to_owned())
                            .unwrap()
                    );
                    conn.write_record(
                        RecordType::ApplicationData,
                        "HTTP 200 OK\r\nit works!\r\n\r\n".as_bytes(),
                    ).unwrap();
                }
                Err(e) => {
                    // Err(Alert("close notify"))
                    println!("\n{:?}", e);
                    break
                }
            }
        }
        // println!("Server data end.");
    }

    #[test]
    fn test_bit() {
        let v = [0u8; 2];
        let mut b = Builder::new(Vec::new());
        b.add_asn1_sequence(|b| {
            b.add_asn1_bit_string(&BitString::new(&v, v.len() * 8));
        });
        println!("{:?}", &b.take().unwrap());
    }
}
