use pnet::datalink::{self, Channel::Ethernet};
use std::thread;
use log::{trace, debug, info, warn, error, LevelFilter};
use clap::Parser;
use colored::*;
use etherparse::PacketHeaders;
use pcap::Capture;
use std::time::Instant;

const HEADER_POUET: usize = 16;

/// Simple mitm bridge between two interfaces
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Interface 0 to sniff
    #[arg(short = '0', long)]
    interface0: Option<String>,

    /// Interface 1 to sniff
    #[arg(short = '1', long)]
    interface1: Option<String>,

    /// Input file with pcap format
    #[arg(short, long)]
    file: Option<String>,

    /// Sniff mode
    #[arg(short, long, action)]
    sniff: bool,

    /// Number of packets to parse from pcap
    #[arg(short, long)]
    packets: Option<i32>,

    /// Attack mode (interface 0 must be connected to UF and interface 1 to HUB !)
    #[arg(short, long, action)]
    attack: bool,
}

struct PouetProtocol {
    address_destination: [u8; 6],
    address_source: [u8; 6]
}

impl PouetProtocol {
    fn display(&self) {
        trace!("adresse de destination :    {:?}", self.address_destination);
        trace!("adresse source :            {:?}", self.address_source);
    }
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    match &args.file {
        Some(file) => {
            let mut nb_packets = args.packets.unwrap_or(-1);
            read_pcap_file(file, &mut nb_packets);
        }
        None => {
            if let Some(interface0) = &args.interface0 {
                if args.sniff {
                    sniff_interface(interface0.to_string());
                } else {
                    if let Some(interface1) = &args.interface1 {
                        mitm(interface0.to_string(), interface1.to_string(), args.attack);
                    } else {
                        debug!("Interface 0 provided, missing interface 1");
                    }
                }
            } else {
                debug!("No input file or interfaces provided");
            }
        }
    }
}

fn read_pcap_file(file: &String, nb_packets: &mut i32) {
    debug!("Reading pcap file {}", file.purple());

    let mut cap = match Capture::from_file(file) {
        Ok(capture) => {
            debug!("Successfully opened {}", file.purple());
            capture
        }
        Err(e) => {
            debug!("Failed to open {} : {}", file.purple(), e);
            return;
        }
    };

    let mut packet_counter: i32 = 1;
    while let Ok(packet) = cap.next_packet() {
        // check max count reached
        if *nb_packets == 0 {
            return;
        }
        read_packet_from_pcap(packet.data, nb_packets, &mut packet_counter);
    }
}

fn mitm(interface0: String, interface1: String, attack: bool) {
    let interfaces = datalink::interfaces();
    let eth0 = match interfaces.into_iter().find(|iface| iface.name == interface0) {
        Some(iface) => {
            debug!("Successfully found interface {}", interface0.blue());
            iface
        }
        None => {
            panic!("Could not find interface {}", interface0.blue());
        }
    };

    let interfaces = datalink::interfaces();
    let eth1 = match interfaces.into_iter().find(|iface| iface.name == interface1) {
        Some(iface) => {
            debug!("Successfully found interface {}", interface1.red());
            iface
        }
        None => {
            panic!("Could not find interface {}", interface1.red());
        }
    };

    // Create data link channels
    let (mut tx0, mut rx0) = match datalink::channel(&eth0, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type for {}", interface0.blue()),
        Err(e) => panic!("Failed to create datalink channel on {}: {}", interface0.blue(), e),
    };

    let (mut tx1, mut rx1) = match datalink::channel(&eth1, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type for {}", interface1.red()),
        Err(e) => panic!("Failed to create datalink channel on {}: {}", interface1.red(), e),
    };

    let interface0_clone = interface0.clone();
    let interface1_clone = interface1.clone();
    // Thread: interface0 → interface1
    let t0 = thread::spawn(move || {
        let mut cpt: i32 = 0;
        loop {
            match rx0.next() {
                Ok(packet) => {
                    cpt += 1;
                    let start = Instant::now();
                    if attack {
                        let packet_modified = modify_packet(packet);
                        if let Some(Err(e)) = tx1.send_to(&packet_modified, None) {
                            error!("Send error {}→{}: {}", interface0.blue(), interface1.red(), e);
                            continue
                        }
                        let elapsed = start.elapsed();
                        debug!("{} -> {} : {} : {} ns : {}", interface0.blue(), interface1.red(), cpt.to_string().yellow(), elapsed.as_nanos(), "modified".red());
                        if attack {
                            debug!("{:?} : {}", packet_modified, "modified".red());
                        }
                    } else {
                        if let Some(Err(e)) = tx1.send_to(packet, None) {
                            error!("Send error {}→{}: {}", interface0.blue(), interface1.red(), e);
                            continue
                        }
                        let elapsed = start.elapsed();
                        debug!("{} -> {} : {} : {} ns", interface0.blue(), interface1.red(), cpt.to_string().yellow(), elapsed.as_nanos());
                    }
                    if log::max_level() < LevelFilter::Trace {
                        debug!("{:?}", packet);
                    }
                    parse(packet);
                }
                Err(e) => error!("Recv error {}: {}", interface0.blue(), e),
            }
        }
    });

    // Thread: interface1 → interface0
    let t1 = thread::spawn(move || {
        let mut cpt: i32 = 0;
        loop {
            match rx1.next() {
                Ok(packet) => {
                    cpt += 1;
                    let start = Instant::now();
                    if let Some(Err(e)) = tx0.send_to(packet, None) {
                        error!("Send error {}→{}: {}", interface1_clone.red(), interface0_clone.blue(), e);
                        continue
                    }
                    let elapsed = start.elapsed();
                    debug!("{} -> {} : {} : {} ns", interface1_clone.red(), interface0_clone.blue(), cpt.to_string().yellow(), elapsed.as_nanos());
                    parse(packet);
                }
                Err(e) => error!("Recv error {}: {}", interface1_clone.red(), e),
            }
        }
    });

    // Wait for threads
    t0.join().unwrap();
    t1.join().unwrap();
}

fn sniff_interface(interface0: String) {
    debug!("Sniffing interface {}", interface0.red());
    let interfaces = datalink::interfaces();
    let eth0 = match interfaces.into_iter().find(|iface| iface.name == interface0) {
        Some(iface) => {
            debug!("Successfully found interface {}", interface0.purple());
            iface
        }
        None => {
            panic!("Could not find interface {}", interface0.purple());
        }
    };

    // Create data link channels
    let (mut _tx0, mut rx0) = match datalink::channel(&eth0, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type for {}", interface0.blue()),
        Err(e) => panic!("Failed to create datalink channel on {}: {}", interface0.blue(), e),
    };

    let mut cpt: i32 = 0;
    loop {
        match rx0.next() {
            Ok(packet) => {
                cpt += 1;
                info!("{} : {}", interface0.blue(), cpt.to_string().yellow());
                trace!("{:?}", packet);
            }
            Err(e) => error!("Recv error {}: {}", interface0.blue(), e),
        }
    }
}



/*
██████   █████  ██████  ███████ ███████ ██████
██   ██ ██   ██ ██   ██ ██      ██      ██   ██
██████  ███████ ██████  ███████ █████   ██████
██      ██   ██ ██   ██      ██ ██      ██   ██
██      ██   ██ ██   ██ ███████ ███████ ██   ██
*/

fn read_packet_from_pcap(data: &[u8], cpt_packet: &mut i32, packet_counter: &mut i32) {
    match PacketHeaders::from_ethernet_slice(data) {
        Ok(_) => {
            trace!("{} {}", "=".repeat(100).cyan(), packet_counter.to_string().yellow());
            parse(data);
            *packet_counter += 1;
            *cpt_packet -= 1;
        }
        Err(e) => {
            warn!("Failed to parse packet: {:?}", e);
        }
    }
}

fn get_pouet_packet(buf: &[u8]) -> Option<PouetProtocol> {
    Some(PouetProtocol {
        address_destination: buf.get(0..6)?.try_into().ok()?,
        address_source: buf.get(6..12)?.try_into().ok()?,
    })
}

fn parse(data: &[u8]) {
    if log::max_level() < LevelFilter::Trace {return}
    trace!("{:?}", data);
    if data.len() < HEADER_POUET {
        error!("error, not enough bytes in pouet packet : {:?}", data);
        return
    }
    let Some(pouet_packet) = get_pouet_packet(&data[0..HEADER_POUET]) else {error!("huh?!");return};
    pouet_packet.display();
}

fn modify_packet(packet: &[u8]) -> Vec<u8> {
    let mut frame = packet.to_vec();

    // modify frame here

    return frame;
}

