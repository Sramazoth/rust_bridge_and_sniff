# help
```bash
Simple mitm bridge between two interfaces

Usage: r_mitm [OPTIONS]

Options:
  -0, --interface0 <INTERFACE0>  Interface 0 to sniff
  -1, --interface1 <INTERFACE1>  Interface 1 to sniff
  -f, --file <FILE>              Input file with pcap format
  -s, --sniff                    Sniff mode
  -p, --packets <PACKETS>        Number of packets to parse from pcap
  -a, --attack                   Attack mode
  -h, --help                     Print help
  -V, --version                  Print version
```

# basic usage
## bridge_and_sniff like scapy
```bash
RUST_LOG=trace cargo run -- --interface0 eth0 --interface0 eth1 # will not modify packets
RUST_LOG=trace cargo run -- --interface0 eth0 --interface0 eth1 --attack # will modify packets depending of `fn modify_packet(...)`
```

## read pcap
```bash
RUST_LOG=trace cargo run -- --file test.pcap # read whole pcap file
RUST_LOG=trace cargo run -- --file test.pcap --packets 5 # only read the first 5 packets
```

![screenshot read pcap](/mitm_rust_image.png)

## sniff mode
Listen packets on an interface (defined with `--interface0`) and display them.