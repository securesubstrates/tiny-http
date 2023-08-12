use crate::connection::Connection;
use crate::util::refined_tcp_stream::Stream as RefinedStream;
use mbedtls::pk;
use mbedtls::pk::EcGroupId;
use mbedtls::rng::{CtrDrbg, Rdseed};
use mbedtls::ssl::config::{
    Endpoint, Preset, Tls13KeyExchangeMode, Transport,
};
use mbedtls::ssl::{
    tls13_preset_default_sig_algs, Tls12CipherSuite, Tls13CipherSuite,
};
use mbedtls::ssl::{Config, Context, Version};
use mbedtls::x509::Certificate;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub(crate) struct MbedTlsStream {
    io: Arc<Mutex<Context<TcpStream>>>,
    peer_addr: Option<SocketAddr>,
}

impl MbedTlsStream {
    pub(crate) fn peer_addr(
        &mut self,
    ) -> std::io::Result<Option<SocketAddr>> {
        Ok(self.peer_addr)
    }

    pub(crate) fn shutdown(
        &mut self,
        how: Shutdown,
    ) -> std::io::Result<()> {
        if let Some(inner_io) = self
            .io
            .lock()
            .expect("Failed to lock SSL stream mutex")
            .io_mut()
        {
            return inner_io.shutdown(how);
        }

        #[cfg(unix)]
        if let Some(inner_io) = self
            .io
            .lock()
            .expect("Failed to lock SSL stream mutex")
            .io_mut()
        {
            return inner_io.shutdown(how);
        }

        Ok(())
    }
}

impl Clone for MbedTlsStream {
    fn clone(&self) -> Self {
        Self {
            io: self.io.clone(),
            peer_addr: self.peer_addr.clone(),
        }
    }
}

impl Read for MbedTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.io
            .lock()
            .expect("Failed to lock SSL stream mutex")
            .read(buf)
    }
}

impl Write for MbedTlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.io
            .lock()
            .expect("Failed to lock SSL stream mutex")
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io
            .lock()
            .expect("Failed to lock SSL stream mutex")
            .flush()
    }
}

pub(crate) struct MbedTlsContext(Arc<Config>);

impl MbedTlsContext {
    pub(crate) fn from_pem(
        certificates: Vec<u8>,
        private_key: Zeroizing<Vec<u8>>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let ciphers: Vec<i32> = vec![
            //
            // TLS 1.3 cipher suite
            //
            Tls13CipherSuite::Tls13Aes256GcmSha384.into(),
            Tls13CipherSuite::Tls13Aes128GcmSha256.into(),
            Tls13CipherSuite::Tls13Aes128CcmSha256.into(),
            //
            // TLS 1.2 cipher suites
            //
            Tls12CipherSuite::EcdheEcdsaWithAes256GcmSha384.into(),
            Tls12CipherSuite::EcdheEcdsaWithAes128GcmSha256.into(),
            Tls12CipherSuite::EcdheRsaWithAes256GcmSha384.into(),
            Tls12CipherSuite::EcdheRsaWithAes128GcmSha256.into(),
            0,
        ];

        let curves: Vec<u32> = vec![
            EcGroupId::SecP384R1.into(),
            EcGroupId::Curve448.into(),
            EcGroupId::SecP256R1.into(),
            EcGroupId::Curve25519.into(),
            0,
        ];

        let mut blinder = CtrDrbg::new(Arc::new(Rdseed), None)?;
        let cert =
            Arc::new(Certificate::from_pem_multiple(&certificates)?);
        let key = Arc::new(pk::Pk::from_private_key(
            &mut blinder,
            &private_key,
            None,
        )?);

        let rng = Arc::new(CtrDrbg::new(Arc::new(Rdseed), None)?);

        let mut cfg = Config::new(
            Endpoint::Server,
            Transport::Stream,
            Preset::Default,
        );
        cfg.set_min_version(Version::Tls12)?;
        cfg.set_rng(rng);
        cfg.push_cert(cert, key)?;
        cfg.set_ciphersuites(Arc::new(ciphers));
        cfg.set_signature_algorithms(Arc::new(
            tls13_preset_default_sig_algs(),
        ));
        cfg.set_tls13_key_exchange_modes(
            Tls13KeyExchangeMode::EPHEMERAL,
        );
        cfg.set_curves(Arc::new(curves));
        Ok(MbedTlsContext(Arc::new(cfg)))
    }

    pub(crate) fn accept(
        &self,
        stream: Connection,
    ) -> Result<MbedTlsStream, Box<dyn Error + Send + Sync + 'static>>
    {
        let cfg = self.0.clone();
        let mut con = Context::new(cfg);
        let addr = match stream {
            Connection::Tcp(tcp) => {
                let addr = tcp.peer_addr();
                con.establish(tcp, None)?;
                addr.ok()
            }
            #[cfg(unix)]
            Connection::Unix(_unix) => {
                // todo!();
                // con.establish(unix, None)?;
                None
            }
        };
        Ok(MbedTlsStream {
            io: Arc::new(Mutex::new(con)),
            peer_addr: addr,
        })
    }
}

impl From<MbedTlsStream> for RefinedStream {
    fn from(stream: MbedTlsStream) -> Self {
        Self::Https(stream)
    }
}
