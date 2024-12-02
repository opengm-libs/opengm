use rand::Rng;

use crate::cipher_suits::CipherSuite;
use crate::config::Config;
use crate::conn::Conn;
use crate::consts::COMPRESSION_NONE;
use crate::finished_hash::FinishedHash;
use crate::key_agreement::get_client_key_agreement;
use crate::messages::{
    Alert, CertificateMsgBorrowed, ClientHelloMsgOwned, FinishedMsgOwned, FinishedMsgBorrowed,
    ServerHelloDoneMsg, ServerHelloMsgBorrowed, ServerKeyExchangeMsgBorrowed,
};
use crate::prf::{
    compute_finished_verify_data, compute_master_secret, KeyBlock,
};
use crate::record::{Record, RecordType};
use crate::traits::Hash;
use crate::x509::certificate::parse_asn1_sm2_public;
use crate::Result;
use crate::{x509, Error};
use std::io;
use std::mem::take;

pub(crate) fn make_client_hello(config: &Config) -> ClientHelloMsgOwned {
    ClientHelloMsgOwned {
        vers: config.version,
        random: config.rng.borrow_mut().gen(),
        session_id: Vec::new(),
        cipher_suite_ids: config.supported_cipher_suites().to_owned(),
        compression_methods: vec![COMPRESSION_NONE],
        raw: None,
    }
}

// precess ServerHelloMsg and returns the neociated (version, cipher_suite_id)
pub fn precess_server_hello(
    client_hello: &ClientHelloMsgOwned,
    server_hello: &ServerHelloMsgBorrowed,
) -> Result<(u16, u16)> {
    // check server_hello.ver
    if server_hello.vers != client_hello.vers{
        return Err(Alert::ProtocolVersion.into())
    }
    let vers = server_hello.vers;
    let suit = server_hello.cipher_suite_id;
    if client_hello.cipher_suite_ids.contains(&suit){
        return Ok((vers, suit))
    }
    return Err(Alert::HandshakeFailure.into())

}
// ClientHandshakeState do the handshake work after receiving server's hello.
pub struct ClientHandshakeState<
    'a,
    C: io::Write + io::Read,
    H: Hash<DIGEST_SIZE> + Default,
    const DIGEST_SIZE: usize,
> {
    pub conn: &'a mut Conn<C>,
    serverHello: ServerHelloMsgBorrowed<'a>,
    hello: ClientHelloMsgOwned,
    version: u16,
    suite: CipherSuite,

    finishedHash: FinishedHash<H, DIGEST_SIZE>,
    masterSecret: Option<[u8; 48]>,
    // session      *ClientSessionSta

    // record buffer
    certificate_record: Record,
    server_key_exchange_record: Record,
    server_hello_done_record: Record,
    client_key_exchange: Record,
    server_finished_record: Record,
}

impl<'a, C, H, const DIGEST_SIZE: usize> Drop for ClientHandshakeState<'a, C, H, DIGEST_SIZE>
where 
    C: io::Write + io::Read,
    H: Hash<DIGEST_SIZE> + Default,
{
    fn drop(&mut self) {
        self.conn
            .record_pool
            .put(take(&mut self.certificate_record));
        self.conn
            .record_pool
            .put(take(&mut self.server_key_exchange_record));
        self.conn
            .record_pool
            .put(take(&mut self.server_hello_done_record));
        self.conn
            .record_pool
            .put(take(&mut self.client_key_exchange));
        self.conn
            .record_pool
            .put(take(&mut self.server_finished_record));
    }
}

impl<
        'a,
        C: io::Write + io::Read,
        H: Hash<DIGEST_SIZE> + Default,
        const DIGEST_SIZE: usize,
    > ClientHandshakeState<'a, C, H, DIGEST_SIZE>
{
    pub fn new(
        conn: &'a mut Conn<C>,
        hello: ClientHelloMsgOwned,
        serverHello: ServerHelloMsgBorrowed<'a>,
        version: u16,
        cipher_suit: CipherSuite,
    ) -> Self {
        let certificate_record = conn.record_pool.get();
        let server_key_exchange_record = conn.record_pool.get();
        let server_hello_done_record = conn.record_pool.get();
        let client_key_exchange = conn.record_pool.get();
        let server_finished_record = conn.record_pool.get();
        ClientHandshakeState {
            conn,
            serverHello,
            hello,
            version,
            suite: cipher_suit,
            finishedHash: FinishedHash::new(),
            masterSecret: None,
            certificate_record,
            server_key_exchange_record,
            server_hello_done_record,
            client_key_exchange,
            server_finished_record,
        }
    }

    pub fn handshake(&mut self) -> Result<()> {
        let conn = &mut *self.conn;

        self.finishedHash.write(self.hello.bytes()?);
        self.finishedHash.write(self.serverHello.bytes()?);
        print!("serverHello.");

        let certificate_record = &mut self.certificate_record;
        conn.read_record(certificate_record)?;
        self.finishedHash
            .write(certificate_record.fragment_as_ref());
        let certificate =
            CertificateMsgBorrowed::parse(certificate_record.fragment_as_ref())
                .ok_or(Alert::UnexpectedMessage)?;
        println!("Server: Certificate");
        // put certificate_record after ward.

        let server_key_exchange_record = &mut self.server_key_exchange_record;
        conn.read_record(server_key_exchange_record)?;
        self.finishedHash
            .write(server_key_exchange_record.fragment_as_ref());
        let server_key_exchange_msg = ServerKeyExchangeMsgBorrowed::parse(
            server_key_exchange_record.fragment_as_ref(),
        )
        .ok_or(Error::from(Alert::UnexpectedMessage))?;
        println!("Server: ServerKeyExchange");

        // ServerHelloDone
        let server_hello_done_record = &mut self.server_hello_done_record;
        conn.read_record(server_hello_done_record)?;
        self.finishedHash
            .write(server_hello_done_record.fragment_as_ref());
        let server_hello_done = ServerHelloDoneMsg::parse(
            server_hello_done_record.fragment_as_ref(),
        )
        .ok_or(Error::from(Alert::UnexpectedMessage))?;
        println!("ServerHelloDoneMsg: {:?}", server_hello_done);

        let mut public_keys = Vec::new();
        for cert in &certificate.certificates {
            public_keys.push(
                parse_asn1_sm2_public(cert)
                    .ok_or(Error::DecodeSM2PublicFailure)?,
            );
        }
        let server_sign_cert = x509::Certificate {
            raw: certificate.certificates[0].to_owned(),
            public_key_algorithm: x509::PublicKeyAlgorithm::ECC,
            public_key: Box::new(public_keys[0].clone()),
        };

        let server_enc_cert = x509::Certificate {
            raw: certificate.certificates[1].to_owned(),
            public_key_algorithm: x509::PublicKeyAlgorithm::ECC,
            public_key: Box::new(public_keys[1].clone()),
        };

        // verify the cert.
        // we see that 1,2 verified by 3, 3 verified by 4, 4 verified by 4.
        // 4 is self signed.
        // let sign_cert = &certificate.certificates[2];
        // let mut parser = Parser::new(sign_cert);
        // let mut certificate = parser.read_asn1_sequence().unwrap();
        // let tbs_certificate = certificate.read_asn1_Object().unwrap();
        // let msg = tbs_certificate.raw.to_owned();
        // let _ = certificate.read_asn1_sequence().unwrap();
        // let signature_value = certificate.read_asn1_bit_string().unwrap();
        // let signature = Parser::new(&signature_value.bytes).decode_sm2_signature().unwrap();

        // for public_key in &public_keys {
        //     let e = sm2::sign::precompute_with_id_public_key_msg(None, &public_key, &msg);
        //     println!("{:?}", verify(&public_key.clone(), &e, &signature));
        // }

        // verify the ServerKeyExchangeMsg
        let mut ka = get_client_key_agreement(self.suite.id, server_enc_cert)
            .ok_or(Error::NoKeyAgreementAvailable)?;
        ka.process_server_key_exchange(
            &self.hello,
            &self.serverHello,
            &server_key_exchange_msg,
            &server_sign_cert,
        )?;
        println!("ServerKeyExchangeMsg verify pass");

        // ClientKeyExchange
        let (pre_master_key, mut client_key_exchange_msg) =
            ka.generate_client_key_exchange()?;
        let client_key_exchange = client_key_exchange_msg.bytes()?;
        self.finishedHash.write(&client_key_exchange);
        println!(
            "ClientKeyExchangeMsg: {:?}",
            conn.write_record(RecordType::Handshake, &client_key_exchange)
                .unwrap()
        );

        // 派生密钥.
        let master_secret = compute_master_secret(
            &pre_master_key,
            &self.hello.random,
            &self.serverHello.random,
        );
        let cipher_suit = &self.suite;
        let key_block = KeyBlock::new(
            &master_secret,
            &self.hello.random,
            &self.serverHello.random,
            cipher_suit.mac_len,
            cipher_suit.key_len,
            cipher_suit.iv_len,
        );

        conn.output.prepare_cipher_spec(
            cipher_suit,
            &key_block.client_write_mac_key,
            &key_block.client_write_key,
            &key_block.client_write_IV,
        );
        conn.input.prepare_cipher_spec(
            cipher_suit,
            &key_block.server_write_mac_key,
            &key_block.server_write_key,
            &key_block.server_write_IV,
        );

        // client ChangeCipherSpec
        println!(
            "client ChangeCipherSpecMsg: {:?}",
            conn.write_change_cipher_spec()?
        );

        // encrypted client Finished
        let hash = self.finishedHash.sum();
        let finished_data =
            compute_finished_verify_data(&master_secret, &hash, true);
        let mut finished_msg = FinishedMsgOwned::new(&finished_data);
        self.finishedHash.write(finished_msg.bytes()?);
        println!(
            "client Finished: {:?}",
            conn.write_record(RecordType::Handshake, finished_msg.bytes()?)?
        );

        // Server ChangeCipherSpec
        conn.read_change_cipher_spec()?;
        conn.input.change_cipher_spec()?; // then change input HalfConn
                                          // record.sink(&mut conn.record_pool);

        // encrypted server Finished
        let mut server_finished_record = conn.record_pool.get();
        conn.read_record(&mut server_finished_record)?;
        let server_finished =
            FinishedMsgBorrowed::parse(server_finished_record.fragment_as_ref())
                .ok_or(Error::InvalidHandshakeMsg)?;
        println!("Server Finished: {:?}", server_finished);
        
        // check server finished
        // server computed client finished data
        let hash = self.finishedHash.sum();
        let server_finished_should_be =
            compute_finished_verify_data(&master_secret, &hash, false);
        if server_finished.verify_data != server_finished_should_be {
            println!("Server Finished shoud be : {:?}", server_finished_should_be);
            return Err(Error::from(Alert::HandshakeFailure));
        }

        Ok(())
    }
}




#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::messages::Alert;
    use crate::Result;
    use crate::{conn::*, record::*};

    #[test]
    fn test_connect() -> Result<()> {
        let mut conn;
        let config = Config::default();
        if false {
            // ebssec.boc.cn: 112.64.122.183
            conn = Conn::connect("112.64.122.183:443", &config)
                .expect("Couldn't connect to the server...");
            conn.handshake()?;
            conn.write_record(
                RecordType::ApplicationData,
                "GET /boc15/scripts/lib/domain.js HTTP/1.0\r\n\r\n".as_bytes(),
            )
            .unwrap();
            println!("Server data:");
            let mut record = conn.record_pool.get();
            loop {
                match conn.read_record(&mut record) {
                    Ok(_) => print!(
                        "{}",
                        String::from_utf8(record.fragment_as_ref().to_owned())
                            .unwrap()
                    ),
                    Err(e) => {
                        println!("\n{:?}", e);
                        break;
                    }
                }
            }
            println!("Server data end.");
        } else {
            conn = Conn::connect("127.0.0.1:8080", &config)
                .expect("Couldn't connect to the server...");
            conn.handshake()?;
            let mut record = conn.record_pool.get();

            for _ in 0..1 {
                conn.write_record(
                    RecordType::ApplicationData,
                        "GET / HTTP/1.0\r\n\r\n".as_bytes(),
                )
                .unwrap();
                match conn.read_record(&mut record) {
                    Ok(()) => print!(
                        "{}\n\n",
                        String::from_utf8(record.fragment_as_ref().to_owned())
                            .unwrap()
                    ),
                    Err(e) => {
                        // Err(Alert("close notify"))
                        println!("\n{:?}", e);
                        break;
                    }
                }
            }
            _ = conn.write_alert(Alert::CloseNotify);
            println!("Server data end.");
        }

        Ok(())
    }
}
