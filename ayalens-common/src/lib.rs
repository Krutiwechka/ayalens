#![no_std]

#[repr(C)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub eth_type: u16,
}

#[repr(C)]
pub struct EthHdrVlan{
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub vlan: [u8; 4],
    pub eth_type: u16,
    
}
#[repr(C)]
pub struct Ipv4Hdr{
    pub ver_and_ihl: u8,
    pub did_serv: u8,
    pub total_len: u16,
    pub ind: u16,
    pub fg_info: u16,
    pub ttl: u8,
    pub protocol: u8, 
    pub checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C)]
pub struct UdpHdr{
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub checksum: u16,
}
#[repr(C)]
pub struct TcpHdr{
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u64,
    pub ack_num: u64,
    pub hdr_len: u8,
    pub flags: u8,
    pub wind_size: u16,
    pub checksum: u16,
    pub urg_ptr: u16,
}

pub mod eth_type {
    pub const IPV4: u16 = 0x0800_u16.to_be(); 
    pub const VLAN: u16 = 0x8100_u16.to_be();
    
}

