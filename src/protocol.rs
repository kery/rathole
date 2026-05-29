pub const HASH_WIDTH_IN_BYTES: usize = 32;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

type ProtocolVersion = u8;
const _PROTO_V0: u8 = 0u8;
const PROTO_V1: u8 = 1u8;

pub const CURRENT_PROTO_VERSION: ProtocolVersion = PROTO_V1;

pub type Digest = [u8; HASH_WIDTH_IN_BYTES];

#[derive(Deserialize, Serialize, Debug)]
pub enum Hello {
    ControlChannelHello(ProtocolVersion, Digest), // sha256sum(service name) or a nonce
    DataChannelHello(ProtocolVersion, Digest),    // token provided by CreateDataChannel
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Auth(pub Digest);

#[derive(Deserialize, Serialize, Debug)]
pub enum Ack {
    Ok,
    ServiceNotExist,
    AuthFailed,
}

impl std::fmt::Display for Ack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Ack::Ok => "Ok",
                Ack::ServiceNotExist => "Service not exist",
                Ack::AuthFailed => "Incorrect token",
            }
        )
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub enum ControlChannelCmd {
    CreateDataChannel,
    HeartBeat,
}

#[derive(Deserialize, Serialize, Debug)]
pub enum DataChannelCmd {
    StartForwardTcp,
    StartForwardUdp,
    /// Dynamic forward: client connects to a target chosen per connection (SOCKS5 CONNECT).
    StartForwardSocks,
}

/// SOCKS5-style address block sent on the data channel after `StartForwardSocks`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksForwardTarget {
    pub atyp: u8,
    pub addr: Vec<u8>,
    pub port: u16,
}

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

impl SocksForwardTarget {
    pub async fn write<T: AsyncWrite + Unpin>(&self, w: &mut T) -> Result<()> {
        w.write_u8(self.atyp).await?;
        match self.atyp {
            ATYP_IPV4 => {
                if self.addr.len() != 4 {
                    bail!("SocksForwardTarget: ipv4 must be 4 bytes");
                }
                w.write_all(&self.addr).await?;
            }
            ATYP_DOMAIN => {
                let len: u8 = self.addr.len().try_into().map_err(|_| {
                    anyhow::Error::msg("SocksForwardTarget: domain too long")
                })?;
                w.write_u8(len).await?;
                w.write_all(&self.addr).await?;
            }
            ATYP_IPV6 => {
                if self.addr.len() != 16 {
                    bail!("SocksForwardTarget: ipv6 must be 16 bytes");
                }
                w.write_all(&self.addr).await?;
            }
            _ => bail!("SocksForwardTarget: invalid atyp {}", self.atyp),
        }
        w.write_u16(self.port).await?;
        w.flush().await?;
        Ok(())
    }

    pub async fn read<T: AsyncRead + Unpin>(r: &mut T) -> Result<Self> {
        let atyp = r.read_u8().await?;
        let addr = match atyp {
            ATYP_IPV4 => {
                let mut v = vec![0u8; 4];
                r.read_exact(&mut v).await?;
                v
            }
            ATYP_DOMAIN => {
                let len = r.read_u8().await? as usize;
                if len == 0 {
                    bail!("SocksForwardTarget: empty domain");
                }
                let mut v = vec![0u8; len];
                r.read_exact(&mut v).await?;
                v
            }
            ATYP_IPV6 => {
                let mut v = vec![0u8; 16];
                r.read_exact(&mut v).await?;
                v
            }
            _ => bail!("SocksForwardTarget: invalid atyp {}", atyp),
        };
        let port = r.read_u16().await?;
        Ok(Self { atyp, addr, port })
    }
}

type UdpPacketLen = u16; // `u16` should be enough for any practical UDP traffic on the Internet
#[derive(Deserialize, Serialize, Debug)]
struct UdpHeader {
    from: SocketAddr,
    len: UdpPacketLen,
}

#[derive(Debug)]
pub struct UdpTraffic {
    pub from: SocketAddr,
    pub data: Bytes,
}

impl UdpTraffic {
    pub async fn write<T: AsyncWrite + Unpin>(&self, writer: &mut T) -> Result<()> {
        let hdr = UdpHeader {
            from: self.from,
            len: self.data.len() as UdpPacketLen,
        };

        let v = bincode::serialize(&hdr).unwrap();

        trace!("Write {:?} of length {}", hdr, v.len());
        writer.write_u8(v.len() as u8).await?;
        writer.write_all(&v).await?;

        writer.write_all(&self.data).await?;

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn write_slice<T: AsyncWrite + Unpin>(
        writer: &mut T,
        from: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        let hdr = UdpHeader {
            from,
            len: data.len() as UdpPacketLen,
        };

        let v = bincode::serialize(&hdr).unwrap();

        trace!("Write {:?} of length {}", hdr, v.len());
        writer.write_u8(v.len() as u8).await?;
        writer.write_all(&v).await?;

        writer.write_all(data).await?;

        Ok(())
    }

    pub async fn read<T: AsyncRead + Unpin>(reader: &mut T, hdr_len: u8) -> Result<UdpTraffic> {
        let mut buf = vec![0; hdr_len as usize];
        reader
            .read_exact(&mut buf)
            .await
            .with_context(|| "Failed to read udp header")?;

        let hdr: UdpHeader =
            bincode::deserialize(&buf).with_context(|| "Failed to deserialize UdpHeader")?;

        trace!("hdr {:?}", hdr);

        let mut data = BytesMut::new();
        data.resize(hdr.len as usize, 0);
        reader.read_exact(&mut data).await?;

        Ok(UdpTraffic {
            from: hdr.from,
            data: data.freeze(),
        })
    }
}

pub fn digest(data: &[u8]) -> Digest {
    use sha2::{Digest, Sha256};
    let d = Sha256::new().chain_update(data).finalize();
    d.into()
}

struct PacketLength {
    hello: usize,
    ack: usize,
    auth: usize,
    c_cmd: usize,
    d_cmd: usize,
}

impl PacketLength {
    pub fn new() -> PacketLength {
        let username = "default";
        let d = digest(username.as_bytes());
        let hello = bincode::serialized_size(&Hello::ControlChannelHello(CURRENT_PROTO_VERSION, d))
            .unwrap() as usize;
        let c_cmd =
            bincode::serialized_size(&ControlChannelCmd::CreateDataChannel).unwrap() as usize;
        let d_cmd = [
            bincode::serialized_size(&DataChannelCmd::StartForwardTcp).unwrap(),
            bincode::serialized_size(&DataChannelCmd::StartForwardUdp).unwrap(),
            bincode::serialized_size(&DataChannelCmd::StartForwardSocks).unwrap(),
        ]
        .into_iter()
        .max()
        .unwrap() as usize;
        let ack = Ack::Ok;
        let ack = bincode::serialized_size(&ack).unwrap() as usize;

        let auth = bincode::serialized_size(&Auth(d)).unwrap() as usize;
        PacketLength {
            hello,
            ack,
            auth,
            c_cmd,
            d_cmd,
        }
    }
}

lazy_static! {
    static ref PACKET_LEN: PacketLength = PacketLength::new();
}

pub async fn read_hello<T: AsyncRead + AsyncWrite + Unpin>(conn: &mut T) -> Result<Hello> {
    let mut buf = vec![0u8; PACKET_LEN.hello];
    conn.read_exact(&mut buf)
        .await
        .with_context(|| "Failed to read hello")?;
    let hello = bincode::deserialize(&buf).with_context(|| "Failed to deserialize hello")?;

    match hello {
        Hello::ControlChannelHello(v, _) => {
            if v != CURRENT_PROTO_VERSION {
                bail!(
                    "Protocol version mismatched. Expected {}, got {}. Please update `rathole`.",
                    CURRENT_PROTO_VERSION,
                    v
                );
            }
        }
        Hello::DataChannelHello(v, _) => {
            if v != CURRENT_PROTO_VERSION {
                bail!(
                    "Protocol version mismatched. Expected {}, got {}. Please update `rathole`.",
                    CURRENT_PROTO_VERSION,
                    v
                );
            }
        }
    }

    Ok(hello)
}

pub async fn read_auth<T: AsyncRead + AsyncWrite + Unpin>(conn: &mut T) -> Result<Auth> {
    let mut buf = vec![0u8; PACKET_LEN.auth];
    conn.read_exact(&mut buf)
        .await
        .with_context(|| "Failed to read auth")?;
    bincode::deserialize(&buf).with_context(|| "Failed to deserialize auth")
}

pub async fn read_ack<T: AsyncRead + AsyncWrite + Unpin>(conn: &mut T) -> Result<Ack> {
    let mut bytes = vec![0u8; PACKET_LEN.ack];
    conn.read_exact(&mut bytes)
        .await
        .with_context(|| "Failed to read ack")?;
    bincode::deserialize(&bytes).with_context(|| "Failed to deserialize ack")
}

pub async fn read_control_cmd<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
) -> Result<ControlChannelCmd> {
    let mut bytes = vec![0u8; PACKET_LEN.c_cmd];
    conn.read_exact(&mut bytes)
        .await
        .with_context(|| "Failed to read cmd")?;
    bincode::deserialize(&bytes).with_context(|| "Failed to deserialize control cmd")
}

pub async fn read_data_cmd<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut T,
) -> Result<DataChannelCmd> {
    let mut bytes = vec![0u8; PACKET_LEN.d_cmd];
    conn.read_exact(&mut bytes)
        .await
        .with_context(|| "Failed to read cmd")?;
    bincode::deserialize(&bytes).with_context(|| "Failed to deserialize data cmd")
}
