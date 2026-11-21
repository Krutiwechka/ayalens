#![no_std]

#[repr(C)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub eth_type: u16,
}

pub mod eth_type {
    pub const IPV4: u16 = 0x0800_u16.to_be(); 
}

