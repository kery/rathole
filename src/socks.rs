//! SOCKS5 server-side handshake (RFC 1928) for dynamic forward.
//! Only NO AUTHENTICATION and CONNECT are supported.

use anyhow::{bail, Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "server")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "server")]
use tokio::net::TcpStream;

use crate::protocol::SocksForwardTarget;

const SOCKS5: u8 = 5;
const CMD_CONNECT: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Perform SOCKS5 handshake on an accepted visitor connection and return the CONNECT target.
#[cfg(feature = "server")]
pub async fn server_handshake(visitor: &mut TcpStream) -> Result<SocksForwardTarget> {
    let ver = visitor.read_u8().await.context("SOCKS: read version")?;
    if ver != SOCKS5 {
        bail!("SOCKS: unsupported version {}", ver);
    }
    let nmethods = visitor
        .read_u8()
        .await
        .context("SOCKS: read nmethods")? as usize;
    let mut methods = vec![0u8; nmethods];
    visitor
        .read_exact(&mut methods)
        .await
        .context("SOCKS: read methods")?;

    // NO AUTHENTICATION REQUIRED
    if !methods.contains(&0) {
        let _ = visitor.write_all(&[SOCKS5, 0xff]).await;
        bail!("SOCKS: no acceptable auth method");
    }
    visitor
        .write_all(&[SOCKS5, 0])
        .await
        .context("SOCKS: write method selection")?;

    let ver = visitor.read_u8().await.context("SOCKS: read req version")?;
    if ver != SOCKS5 {
        bail!("SOCKS: bad request version {}", ver);
    }
    let cmd = visitor.read_u8().await.context("SOCKS: read cmd")?;
    if cmd != CMD_CONNECT {
        socks_reply(visitor, 0x07).await?; // Command not supported
        bail!("SOCKS: unsupported cmd {}", cmd);
    }
    let _rsv = visitor.read_u8().await.context("SOCKS: read rsv")?;
    let atyp = visitor.read_u8().await.context("SOCKS: read atyp")?;

    let addr = match atyp {
        ATYP_IPV4 => {
            let mut v = [0u8; 4];
            visitor
                .read_exact(&mut v)
                .await
                .context("SOCKS: read ipv4")?;
            v.to_vec()
        }
        ATYP_DOMAIN => {
            let len = visitor.read_u8().await.context("SOCKS: read domain len")? as usize;
            if len == 0 {
                socks_reply(visitor, 0x04).await?;
                bail!("SOCKS: empty domain");
            }
            let mut v = vec![0u8; len];
            visitor
                .read_exact(&mut v)
                .await
                .context("SOCKS: read domain")?;
            v
        }
        ATYP_IPV6 => {
            let mut v = [0u8; 16];
            visitor
                .read_exact(&mut v)
                .await
                .context("SOCKS: read ipv6")?;
            v.to_vec()
        }
        _ => {
            socks_reply(visitor, 0x08).await?;
            bail!("SOCKS: unsupported address type {}", atyp);
        }
    };

    let port = visitor
        .read_u16()
        .await
        .context("SOCKS: read port")?;

    socks_reply(visitor, 0).await?;

    Ok(SocksForwardTarget { atyp, addr, port })
}

#[cfg(feature = "server")]
async fn socks_reply(visitor: &mut TcpStream, rep: u8) -> Result<()> {
    // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
    visitor
        .write_all(&[SOCKS5, rep, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    visitor.flush().await?;
    Ok(())
}

/// Build a `host:port` string for `TcpStream::connect`.
#[cfg(feature = "client")]
pub fn target_to_connect_addr(t: &SocksForwardTarget) -> Result<String> {
    let s = match t.atyp {
        ATYP_IPV4 => {
            if t.addr.len() != 4 {
                bail!("invalid ipv4 length");
            }
            let ip = Ipv4Addr::new(t.addr[0], t.addr[1], t.addr[2], t.addr[3]);
            format!("{}:{}", ip, t.port)
        }
        ATYP_DOMAIN => {
            let host = std::str::from_utf8(&t.addr).context("SOCKS target domain is not UTF-8")?;
            format!("{}:{}", host, t.port)
        }
        ATYP_IPV6 => {
            if t.addr.len() != 16 {
                bail!("invalid ipv6 length");
            }
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&t.addr[..]).unwrap());
            format!("[{}]:{}", ip, t.port)
        }
        _ => bail!("invalid atyp {}", t.atyp),
    };
    Ok(s)
}
