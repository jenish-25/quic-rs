//! UDP socket setup and the packet-receive loop.

use std::os::fd::{AsFd, AsRawFd};
use std::str::FromStr;

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, SockaddrIn, bind, recvfrom, setsockopt, socket,
    sockopt::ReuseAddr,
};

use crate::packet::decrypt_initial;

/// Binds a non-blocking UDP socket on `0.0.0.0:3000`, waits for the first QUIC
/// Initial packet, decrypts it, and prints the result.
pub fn run() {
    let sock_addr = SockaddrIn::from_str("0.0.0.0:3000").unwrap();

    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .unwrap();

    // Put the socket into non-blocking mode so `recvfrom` never blocks; `poll`
    // decides when data is ready.
    let flags = OFlag::from_bits_truncate(fcntl(&fd, FcntlArg::F_GETFL).unwrap());
    fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();

    setsockopt(&fd, ReuseAddr, &true).unwrap();
    bind(fd.as_raw_fd(), &sock_addr).unwrap();

    loop {
        println!("Polling for a QUIC Initial packet on 0.0.0.0:3000");

        let ready = poll(
            &mut [PollFd::new(fd.as_fd(), PollFlags::POLLIN)],
            PollTimeout::from(1000u16),
        )
        .unwrap();

        if ready >= 1 {
            // QUIC requires a client's Initial datagram to be at least 1200 bytes.
            let mut recv_buf = vec![0u8; 1200];
            let (n, _addr) = recvfrom::<SockaddrIn>(fd.as_raw_fd(), &mut recv_buf).unwrap();
            recv_buf.truncate(n);

            match decrypt_initial(&recv_buf) {
                Ok(packet) => {
                    println!("Decrypted Initial packet:");
                    println!("  version       = {:#010x}", packet.version);
                    println!("  dcid          = {}", hex::encode(&packet.dcid));
                    println!("  scid          = {}", hex::encode(&packet.scid));
                    println!("  packet number = {}", packet.packet_number);
                    println!("  frames        = {}", hex::encode(&packet.frames));
                }
                Err(e) => println!("Failed to parse Initial packet: {e}"),
            }

            break;
        }
    }
}
