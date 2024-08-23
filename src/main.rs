use std::{
    env::{self, args},
    net::{IpAddr, Ipv6Addr},
    thread::sleep,
    time::{Duration, Instant},
};

use error_stack::{Result, ResultExt};
use pnet::{
    packet::{
        self,
        icmpv6::{self, Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet},
        ip::IpNextHeaderProtocols,
    },
    transport::icmpv6_packet_iter,
};
use thiserror::Error;
use tracing::debug;

#[derive(Error, Debug)]
enum AppError {
    #[error("fatal io error")]
    FatalIO,
    #[error("failed to receive packet")]
    PacketReceive,
    #[error("failed to setup socket")]
    Setup,
    #[error("Got wrong arguments")]
    ArgError,
}

#[derive(Debug)]
enum PingResponse {
    Timeout,
    TimeExceeded(IpAddr),
    Response(IpAddr),
}

#[derive(Error, Debug)]
enum ArgError {
    #[error("Not enough arguments, expected 2")]
    NotEnoughArguments,
    #[error("Could not parse \"{0}\" as an Ipv6 address")]
    InvalidAddress(String),
}

#[derive(Debug)]
struct Args {
    source: Ipv6Addr,
    dest: Ipv6Addr,
}

fn parse_arguments() -> Result<Args, ArgError> {
    let mut args = env::args();
    let _program_name = args
        .next()
        .expect("Please don't go around execing things without a 0th argument");

    let [source, dest] = args
        .take(2)
        .map(|arg| {
            arg.parse::<Ipv6Addr>()
                .change_context(ArgError::InvalidAddress(arg))
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| ArgError::NotEnoughArguments)?;

    Ok(Args { source, dest })
}

fn main() -> Result<(), AppError> {
    let mut buffer = [0; 512];
    let (mut send, mut recv) = pnet::transport::transport_channel(
        512,
        pnet::transport::TransportChannelType::Layer4(pnet::transport::TransportProtocol::Ipv6(
            IpNextHeaderProtocols::Icmpv6,
        )),
    )
    .change_context(AppError::Setup)?;

    let Args { source, dest } = parse_arguments().change_context(AppError::ArgError)?;
    let code = Icmpv6Code(0);

    let mut ttl = 1;
    loop {
        send.set_ttl(ttl).change_context(AppError::Setup)?;
        ttl += 1;
        let mut mut_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
        mut_packet.populate(&packet::icmpv6::Icmpv6 {
            icmpv6_type: Icmpv6Types::EchoRequest,
            icmpv6_code: code,
            checksum: 0,
            payload: vec![0u8; 10],
        });

        let packet = mut_packet.to_immutable();

        let checksum = icmpv6::checksum(&packet, &source, &dest);

        mut_packet.set_checksum(checksum);

        let packet = mut_packet.consume_to_immutable();
        send.send_to(packet, dest.into())
            .change_context(AppError::FatalIO)?;
        let send_time = Instant::now();
        let timeout = Duration::from_millis(100);

        let mut packet_iter = icmpv6_packet_iter(&mut recv);

        let response_addr = loop {
            let Some(remaining) = timeout.checked_sub(send_time.elapsed()) else {
                break PingResponse::Timeout;
            };
            let Some((packet, response_addr)) = packet_iter
                .next_with_timeout(remaining)
                .change_context(AppError::PacketReceive)?
            else {
                break PingResponse::Timeout;
            };

            match packet.get_icmpv6_type() {
                Icmpv6Types::EchoReply => {
                    if packet.get_icmpv6_code() == code {
                        break PingResponse::Response(response_addr);
                    } else {
                        debug!("Received answer with mismatching code");
                    }
                }
                Icmpv6Types::TimeExceeded => break PingResponse::TimeExceeded(response_addr),
                Icmpv6Types::NeighborAdvert
                | Icmpv6Types::NeighborSolicit
                | Icmpv6Types::RouterAdvert
                | Icmpv6Types::RouterSolicit => {
                    // Do nothing
                }
                unhandled => todo!("Unhandled: {unhandled:#?}"),
            }

            // break Ok(response_addr);
        };
        match response_addr {
            PingResponse::Response(addr) => {
                println!("Ping Response from {addr:?}");
                break;
            }
            PingResponse::TimeExceeded(addr) => {
                println!("Hop {:2}: {addr:?}", ttl - 1);
            }
            PingResponse::Timeout => {
                println!("Hop {}: TIMEOUT", ttl - 1);
            }
        }
        sleep(Duration::from_millis(100));
    }
    // send.send_to(, )
    Ok(())
}
