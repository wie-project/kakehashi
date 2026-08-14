//! TLS-wrapped guest FDs for freestanding libcurl (path B).
//!
//! Host owns a rustls [`ClientConnection`] per guest FD. Wire I/O uses the
//! host socket fd in the process FD table; guest `read`/`write` see **plaintext**.
//!
//! Created by [`connect`] via `KH_HELPER_TLS_CONNECT`. Not used by Darwin curl
//! (that path has guest OpenSSL + raw sockets).
//!
//! ## Wire-flush invariants
//!
//! 1. Ciphertext taken from rustls via `write_tls` is never discarded: any
//!    unsent bytes live in [`TlsSlot::pending_out`] until the socket accepts
//!    them (TCP send buffer full → `EAGAIN` is common on multi‑GiB POSTs/packs).
//! 2. After `process_new_packets`, always try to flush — TLS 1.3 KeyUpdate and
//!    similar post-handshake messages set `wants_write` during a read path.
//! 3. Guest plaintext is only accepted into rustls after pending ciphertext is
//!    fully written (avoids double-buffering the same app bytes on retry).
//! 4. Call `process_new_packets` after **every** successful `read_tls`. Feeding
//!    many TLS records from one TCP segment without processing fills rustls's
//!    deframer (`message buffer full`) — seen on large git pack downloads.

#![allow(unsafe_code)] // raw host socket I/O around rustls

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::mem::ManuallyDrop;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
};

/// Flag: verify peer certificate against CA bundle (matches freestanding curl).
pub const TLS_FLAG_VERIFY: u32 = 1;
/// Flag: plain TCP only (no rustls). Freestanding libcurl uses this for `http://`.
///
/// Mutually exclusive with TLS semantics: when set, peer verify / CA are ignored
/// and the guest FD is a normal socket (not a TLS-wrapped plaintext view).
pub const TLS_FLAG_PLAIN: u32 = 2;

struct TlsSlot {
    conn: ClientConnection,
    /// Ciphertext extracted from rustls but not yet fully written to the socket.
    pending_out: Vec<u8>,
    /// Wire bytes not yet accepted by `read_tls` (left when we stop to drain
    /// plaintext, or after a deframer-full recovery).
    pending_in: Vec<u8>,
}

static SLOTS: Mutex<Option<HashMap<i32, TlsSlot>>> = Mutex::new(None);

fn with_slots<R>(f: impl FnOnce(&mut HashMap<i32, TlsSlot>) -> R) -> R {
    let mut guard = SLOTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// True when this guest FD has a host-side TLS session.
///
/// Hot path uses a lock-free FD flag (see [`crate::process::fd_is_tls`]).
#[must_use]
#[inline]
pub fn is_tls_fd(gfd: i32) -> bool {
    crate::process::fd_is_tls(gfd)
}

/// Run a rustls client handshake on an already-connected guest TCP socket.
///
/// Darwin rustup uses SecureTransport (`SSLHandshake`) on a raw `connect`'d
/// fd. After this, guest `read`/`write` on `gfd` are plaintext (same as
/// [`connect`]).
pub fn wrap_existing(gfd: i32, hostname: &str) -> Result<(), String> {
    if is_tls_fd(gfd) {
        return Ok(());
    }
    let host_fd = crate::process::fd_get(gfd).ok_or_else(|| "bad guest fd".to_owned())?;
    let ca = crate::bottle::active_ca_pem_path();
    let config = build_config(ca.is_some(), ca.as_deref())?;
    let sni = if hostname.is_empty() {
        "localhost"
    } else {
        hostname
    };
    let server_name =
        ServerName::try_from(sni.to_owned()).map_err(|e| format!("server name: {e}"))?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("tls client: {e}"))?;
    // SAFETY: `host_fd` stays in the guest FD table. `ManuallyDrop` so an
    // error path must not `close` it (that was EBADF → rustup abort 134).
    let mut sock = ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(host_fd) });
    // Guest `connect` is non-blocking (EINPROGRESS). Wait until the TCP
    // handshake finishes so rustls does not write to an unconnected socket.
    if !crate::host::poll_fd_writable(host_fd, 15_000) {
        return Err("connect wait timeout".into());
    }
    drop(sock.set_nonblocking(false));
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut *sock) {
            drop(sock.set_nonblocking(true));
            return Err(format!("tls handshake: {e}"));
        }
    }
    drop(conn.complete_io(&mut *sock));
    drop(sock.set_nonblocking(true));
    crate::process::fd_set_tls(gfd, true);
    with_slots(|m| {
        m.insert(
            gfd,
            TlsSlot {
                conn,
                pending_out: Vec::new(),
                pending_in: Vec::new(),
            },
        );
    });
    tracing::debug!(%hostname, gfd, host_fd, "tls_fd wrap ok");
    Ok(())
}

/// Drop TLS state for `gfd` (does not close the host socket).
pub fn take_tls(gfd: i32) -> bool {
    crate::process::fd_set_tls(gfd, false);
    with_slots(|m| m.remove(&gfd).is_some())
}

fn wants_write(gfd: i32) -> bool {
    with_slots(|m| {
        m.get(&gfd)
            .is_some_and(|s| !s.pending_out.is_empty() || s.conn.wants_write())
    })
}

fn has_pending_in(gfd: i32) -> bool {
    with_slots(|m| m.get(&gfd).is_some_and(|s| !s.pending_in.is_empty()))
}

/// TCP connect (+ optional rustls handshake); install guest FD.
///
/// - Default / `TLS_FLAG_VERIFY`: TCP + rustls; guest `read`/`write` are
///   **plaintext** (TLS-wrapped host socket).
/// - `TLS_FLAG_PLAIN`: raw TCP only (for freestanding `http://`); no rustls
///   slot — guest sees wire bytes directly.
///
/// On success returns guest FD. Host socket is non-blocking; guest flag starts
/// **blocking** so freestanding HTTP can `read` without a poll loop.
pub fn connect(
    hostname: &str,
    port: u16,
    flags: u32,
    ca_pem: Option<&Path>,
) -> Result<i32, String> {
    if hostname.is_empty() {
        return Err("empty hostname".into());
    }
    if port == 0 {
        return Err("invalid port".into());
    }

    if flags & TLS_FLAG_PLAIN != 0 {
        return connect_plain(hostname, port);
    }

    let config = build_config((flags & TLS_FLAG_VERIFY) != 0, ca_pem)?;
    let server_name =
        ServerName::try_from(hostname.to_owned()).map_err(|e| format!("server name: {e}"))?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("tls client: {e}"))?;

    let mut sock = tcp_connect_stream(hostname, port)?;
    // Handshake needs blocking I/O.
    sock.set_nonblocking(false)
        .map_err(|e| format!("set blocking: {e}"))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)
            .map_err(|e| format!("tls handshake: {e}"))?;
    }
    drop(conn.complete_io(&mut sock));

    sock.set_nonblocking(true)
        .map_err(|e| format!("set nonblocking: {e}"))?;
    apply_socket_opts(&sock);

    let host_fd = sock.into_raw_fd();
    let Some(gfd) = crate::process::fd_alloc(host_fd) else {
        let _ = unsafe { libc::close(host_fd) };
        return Err("guest fd table full".into());
    };
    crate::process::fd_set_guest_nonblock(gfd, false);
    crate::process::fd_set_tls(gfd, true);

    with_slots(|m| {
        m.insert(
            gfd,
            TlsSlot {
                conn,
                pending_out: Vec::new(),
                pending_in: Vec::new(),
            },
        );
    });

    tracing::debug!(%hostname, port, gfd, host_fd, "tls_fd connect ok");
    Ok(gfd)
}

/// Plain TCP → guest FD (no TLS slot). Used for freestanding `http://`.
fn connect_plain(hostname: &str, port: u16) -> Result<i32, String> {
    let sock = tcp_connect_stream(hostname, port)?;
    sock.set_nonblocking(true)
        .map_err(|e| format!("set nonblocking: {e}"))?;
    apply_socket_opts(&sock);

    let host_fd = sock.into_raw_fd();
    let Some(gfd) = crate::process::fd_alloc(host_fd) else {
        let _ = unsafe { libc::close(host_fd) };
        return Err("guest fd table full".into());
    };
    crate::process::fd_set_guest_nonblock(gfd, false);
    // Explicit: not a TLS FD (default is false; keep clear for clarity).
    crate::process::fd_set_tls(gfd, false);

    tracing::debug!(%hostname, port, gfd, host_fd, "tcp plain connect ok");
    Ok(gfd)
}

fn tcp_connect_stream(hostname: &str, port: u16) -> Result<TcpStream, String> {
    let addr = format!("{hostname}:{port}");
    let sock = TcpStream::connect(&addr).map_err(|e| format!("tcp connect {addr}: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(600)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    sock.set_write_timeout(Some(Duration::from_secs(600)))
        .map_err(|e| format!("set write timeout: {e}"))?;
    Ok(sock)
}

fn apply_socket_opts(sock: &TcpStream) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 {
            let _ = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        }
    }

    // Prefer low latency on small HTTP headers / progress; large packs still
    // stream in multi‑KiB records.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd;
        let raw = sock.as_raw_fd();
        let yes: libc::c_int = 1;
        let yes_len = libc::socklen_t::try_from(core::mem::size_of_val(&yes)).unwrap_or(0);
        let _ = unsafe {
            libc::setsockopt(
                raw,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                core::ptr::from_ref(&yes).cast(),
                yes_len,
            )
        };
        // Larger receive window helps multi‑GiB pack downloads.
        let rcv: libc::c_int = 4 * 1024 * 1024;
        let rcv_len = libc::socklen_t::try_from(core::mem::size_of_val(&rcv)).unwrap_or(0);
        let _ = unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                core::ptr::from_ref(&rcv).cast(),
                rcv_len,
            )
        };
        let snd: libc::c_int = 4 * 1024 * 1024;
        let snd_len = libc::socklen_t::try_from(core::mem::size_of_val(&snd)).unwrap_or(0);
        let _ = unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                core::ptr::from_ref(&snd).cast(),
                snd_len,
            )
        };
    }
}

/// Plaintext read from a TLS guest FD (emulates blocking when guest NB is clear).
///
/// Fills as much of `buf` as currently available (multiple TLS records / wire
/// reads) to cut guest↔host hypercall crossings on multi‑GiB pack downloads.
pub fn read(gfd: i32, host_fd: RawFd, buf: &mut [u8], guest_blocking: bool) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let mut total = 0_usize;
    loop {
        let Some(dst) = buf.get_mut(total..) else {
            return Ok(total);
        };
        if dst.is_empty() {
            return Ok(total);
        }
        match try_read(gfd, host_fd, dst) {
            Ok(0) => return Ok(total), // EOF (only after some data, or true EOF)
            Ok(n) => {
                total = total.saturating_add(n);
                if total >= buf.len() {
                    return Ok(total);
                }
                // More room: pull any already-buffered plaintext / pending wire
                // without blocking on the socket (loop continues).
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if total > 0 {
                    // Short read with data already in hand — normal for read(2).
                    return Ok(total);
                }
                if !guest_blocking {
                    return Err(e);
                }
                // POLLOUT for KeyUpdate / pending ciphertext. pending_in: retry
                // without poll so leftover wire is drained.
                if wants_write(gfd) {
                    drop(flush_tls(gfd, host_fd));
                    if !crate::host::poll_fd_io(host_fd, -1) {
                        return Err(e);
                    }
                } else if !has_pending_in(gfd) && !crate::host::poll_fd_readable(host_fd, -1) {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Plaintext write to a TLS guest FD.
pub fn write(gfd: i32, host_fd: RawFd, buf: &[u8], guest_blocking: bool) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        match try_write(gfd, host_fd, buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if !guest_blocking {
                    return Err(e);
                }
                if !crate::host::poll_fd_io(host_fd, -1) {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

fn try_read_plain(gfd: i32, buf: &mut [u8]) -> io::Result<Option<usize>> {
    with_slots(|m| {
        let Some(slot) = m.get_mut(&gfd) else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        match slot.conn.reader().read(buf) {
            Ok(0) => Ok(Some(0_usize)),
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    })
}

fn is_message_buffer_full(err: &io::Error) -> bool {
    let s = err.to_string();
    s.contains("message buffer full") || s.contains("MessageBufferFull")
}

/// Feed `pending_in` into rustls. Process after every `read_tls` so a multi-record
/// TCP segment cannot fill the deframer. Stop once plaintext is available.
fn feed_pending_in(gfd: i32) -> io::Result<()> {
    with_slots(|m| {
        let Some(slot) = m.get_mut(&gfd) else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        loop {
            if slot.pending_in.is_empty() {
                return Ok(());
            }
            let (read_res, consumed) = {
                let mut cursor = slot.pending_in.as_slice();
                let before = cursor.len();
                let res = slot.conn.read_tls(&mut cursor);
                let n = before.saturating_sub(cursor.len());
                (res, n)
            };
            match read_res {
                Ok(0) => {
                    slot.conn
                        .process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    return Ok(());
                }
                Ok(_) => {
                    if consumed == 0 {
                        return Ok(());
                    }
                    if consumed <= slot.pending_in.len() {
                        slot.pending_in.drain(..consumed);
                    } else {
                        slot.pending_in.clear();
                    }
                    let io_state = slot
                        .conn
                        .process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    if io_state.plaintext_bytes_to_read() > 0 {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if is_message_buffer_full(&e) => {
                    let io_state = slot
                        .conn
                        .process_new_packets()
                        .map_err(|e2| io::Error::new(io::ErrorKind::InvalidData, e2))?;
                    if io_state.plaintext_bytes_to_read() > 0 {
                        return Ok(());
                    }
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
    })
}

fn try_read(gfd: i32, host_fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    match flush_tls(gfd, host_fd) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }

    if let Some(n) = try_read_plain(gfd, buf)? {
        return Ok(n);
    }

    feed_pending_in(gfd)?;
    if let Some(n) = try_read_plain(gfd, buf)? {
        return Ok(n);
    }

    // 16 KiB wire read (stack). Guest fill-loop in `read` amortizes hypercalls.
    let mut wire = [0_u8; 16 * 1024];
    let nr = match read_raw(host_fd, &mut wire) {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Err(e),
        Err(e) => return Err(e),
    };
    if nr == 0 {
        feed_pending_in(gfd)?;
        return match try_read_plain(gfd, buf)? {
            Some(n) => Ok(n),
            None => Ok(0),
        };
    }
    with_slots(|m| {
        let Some(slot) = m.get_mut(&gfd) else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        if let Some(bytes) = wire.get(..nr) {
            slot.pending_in.extend_from_slice(bytes);
        }
        Ok(())
    })?;

    feed_pending_in(gfd)?;

    match flush_tls(gfd, host_fd) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }

    match try_read_plain(gfd, buf)? {
        Some(n) => Ok(n),
        None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
    }
}

fn try_write(gfd: i32, host_fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    flush_tls(gfd, host_fd)?;

    let written = with_slots(|m| {
        let Some(slot) = m.get_mut(&gfd) else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        let n = slot.conn.writer().write(buf)?;
        Ok(n)
    })?;

    match flush_tls(gfd, host_fd) {
        Ok(()) => Ok(written),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock && written > 0 => Ok(written),
        Err(e) => Err(e),
    }
}

fn requeue_unsent(gfd: i32, unsent: &[u8]) {
    if unsent.is_empty() {
        return;
    }
    with_slots(|m| {
        if let Some(slot) = m.get_mut(&gfd) {
            let mut merged = unsent.to_vec();
            merged.append(&mut slot.pending_out);
            slot.pending_out = merged;
        }
    });
}

fn flush_tls(gfd: i32, host_fd: RawFd) -> io::Result<()> {
    loop {
        loop {
            let (chunk, empty) = with_slots(|m| {
                let Some(slot) = m.get_mut(&gfd) else {
                    return Err(io::Error::from_raw_os_error(libc::EBADF));
                };
                if slot.pending_out.is_empty() {
                    return Ok((Vec::new(), true));
                }
                let take = slot.pending_out.len().min(16 * 1024);
                let chunk = slot.pending_out.drain(..take).collect::<Vec<u8>>();
                Ok((chunk, false))
            })?;
            if empty {
                break;
            }
            let mut off = 0_usize;
            while off < chunk.len() {
                let Some(rest) = chunk.get(off..) else {
                    break;
                };
                match write_raw(host_fd, rest) {
                    Ok(0) => {
                        requeue_unsent(gfd, chunk.get(off..).unwrap_or(&[]));
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "tls wire write zero",
                        ));
                    }
                    Ok(w) => off = off.saturating_add(w),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        requeue_unsent(gfd, chunk.get(off..).unwrap_or(&[]));
                        return Err(e);
                    }
                    Err(e) => {
                        requeue_unsent(gfd, chunk.get(off..).unwrap_or(&[]));
                        return Err(e);
                    }
                }
            }
        }

        let extracted = with_slots(|m| {
            let Some(slot) = m.get_mut(&gfd) else {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            };
            if !slot.conn.wants_write() {
                return Ok(0_usize);
            }
            let mut wire = [0_u8; 16 * 1024];
            let mut out = TlsWireBuf {
                buf: &mut wire,
                filled: 0,
            };
            match slot.conn.write_tls(&mut out) {
                Ok(0) => Ok(0_usize),
                Ok(_) => {
                    let n = out.filled;
                    if let Some(bytes) = wire.get(..n) {
                        slot.pending_out.extend_from_slice(bytes);
                    }
                    Ok(n)
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0_usize),
                Err(e) => Err(e),
            }
        })?;
        if extracted == 0 {
            return Ok(());
        }
    }
}

struct TlsWireBuf<'a> {
    buf: &'a mut [u8],
    filled: usize,
}

impl Write for TlsWireBuf<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let space = self.buf.len().saturating_sub(self.filled);
        if space == 0 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = space.min(data.len());
        let end = self.filled.saturating_add(n);
        let Some(dst) = self.buf.get_mut(self.filled..end) else {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        };
        let Some(src) = data.get(..n) else {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        };
        dst.copy_from_slice(src);
        self.filled = end;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_raw(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(n).unwrap_or(0))
}

fn write_raw(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(n).unwrap_or(0))
}

fn build_config(verify: bool, ca_pem: Option<&Path>) -> Result<ClientConfig, String> {
    if !verify {
        let verifier = Arc::new(NoCertVerify);
        return Ok(ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth());
    }

    let mut roots = RootCertStore::empty();
    let path = ca_pem.ok_or_else(|| "CA bundle path required when verify is on".to_owned())?;
    let pem = std::fs::read(path).map_err(|e| format!("read CA {}: {e}", path.display()))?;
    let mut cursor = std::io::Cursor::new(pem);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse CA PEM: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certs in CA bundle {}", path.display()));
    }
    for c in certs {
        roots.add(c).map_err(|e| format!("add CA cert: {e}"))?;
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[derive(Debug)]
struct NoCertVerify;

impl ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}
