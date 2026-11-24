#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_PASS},
    btf_maps::LruPerCpuHashMap,
    macros::{btf_map, xdp},
    programs::XdpContext,
};
use ayalens_common::{
    EthHdr, EthHdrVlan, FlowInfo, FlowTuple, Ipv4Hdr, TcpHdr, UdpHdr, eth_type, protocol,
};
use core::ptr;
#[btf_map(name = "LENS")]
static LENS: LruPerCpuHashMap<FlowTuple, FlowInfo, 16384> = LruPerCpuHashMap::new();

#[xdp]
pub fn ayalens(ctx: XdpContext) -> u32 {
    try_parse(&ctx)
}
fn try_parse(ctx: &XdpContext) -> u32 {
    let (eth_type, mut offset) = match parse_eth(ctx) {
        Ok(eth_type) => eth_type,
        Err(err) => return err,
    };
    let dst_addr: u32;
    let src_addr: u32;
    let protocol: u8;
    let src_port: u16;
    let dst_port: u16;
    match eth_type {
        eth_type::IPV4 => match parse_ipv4(ctx, offset) {
            Ok((src, dst, pr, off)) => {
                dst_addr = dst;
                src_addr = src;
                protocol = pr;
                offset = off;
            }
            Err(err) => return err,
        },
        _ => {
            return XDP_PASS;
        }
    };
    match parse_transport(ctx, protocol, offset) {
        Ok((src, dst, off)) => {
            src_port = src;
            dst_port = dst;
            offset = off;
        }
        Err(err) => return err,
    }
    let flow_tuple = FlowTuple {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        _pad: [0; 3],
    };
    match LENS.get_ptr_mut(flow_tuple) {
        Some(ptr) => {
            let f = unsafe { &mut *ptr };
            f.pkts += 1;
            f.bytes += (ctx.data_end() - ctx.data()) as u64;
        }
        None => {
            let _ = LENS.insert(
                flow_tuple,
                FlowInfo {
                    pkts: 1,
                    bytes: (ctx.data_end() - ctx.data()) as u64,
                },
                0,
            );
        }
    }
    xdp_action::XDP_PASS
}

fn parse_eth(ctx: &XdpContext) -> Result<(u16, usize), u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let mut offset = size_of::<EthHdr>();
    let eth_end = data + offset;
    if eth_end > data_end {
        return Err(xdp_action::XDP_PASS);
    }
    let eth_hdr = data as *const EthHdr;
    let mut eth_type = unsafe { ptr::read_unaligned(ptr::addr_of!((*eth_hdr).eth_type)) };
    if eth_type == eth_type::VLAN {
        offset = size_of::<EthHdrVlan>();
        let eth_end_vlan = data + offset;
        if eth_end_vlan > data_end {
            return Err(xdp_action::XDP_PASS);
        }
        let eth_hdr_vlan = data as *const EthHdrVlan;
        eth_type = unsafe { ptr::read_unaligned(ptr::addr_of!((*eth_hdr_vlan).eth_type)) };
    }
    Ok((eth_type, offset))
}
fn parse_ipv4(ctx: &XdpContext, offset: usize) -> Result<(u32, u32, u8, usize), u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let ip_start = data + offset;
    if ip_start + size_of::<Ipv4Hdr>() > data_end {
        return Err(xdp_action::XDP_PASS);
    }
    let ip_hdr = ip_start as *const Ipv4Hdr;
    let ver = unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).ver_and_ihl)) } >> 4;
    if ver != 4 {
        return Err(xdp_action::XDP_PASS);
    }
    let ihl =
        (unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).ver_and_ihl)) } & 0b00001111) * 4;
    let raw_offset = offset + ihl as usize;
    if raw_offset + data > data_end {
        return Err(xdp_action::XDP_PASS);
    }
    if ihl < 20 {
        return Err(xdp_action::XDP_PASS);
    }
    let fg_off = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).fg_info)) })
        & 0b0001_1111_1111_1111;
    if fg_off != 0 {
        return Err(xdp_action::XDP_PASS);
    }
    let protocol = unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).protocol)) };
    let src_addr = u32::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).src_addr)) });
    let dst_addr = u32::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*ip_hdr).dst_addr)) });
    Ok((src_addr, dst_addr, protocol, raw_offset))
}

fn parse_transport(
    ctx: &XdpContext,
    protocol: u8,
    offset: usize,
) -> Result<(u16, u16, usize), u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let src_port: u16;
    let dst_port: u16;
    let raw_offset: usize;
    match protocol {
        protocol::UDP => {
            let hdr_start = data + offset;
            if hdr_start + size_of::<UdpHdr>() > data_end {
                return Err(xdp_action::XDP_PASS);
            }
            raw_offset = offset + size_of::<UdpHdr>();
            let hdr = hdr_start as *const UdpHdr;
            src_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*hdr).src_port)) });
            dst_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*hdr).dst_port)) });
        }
        protocol::TCP => {
            let hdr_start = data + offset;
            if hdr_start + size_of::<TcpHdr>() > data_end {
                return Err(xdp_action::XDP_PASS);
            }
            let hdr = hdr_start as *const TcpHdr;
            let len = (unsafe { ptr::read_unaligned(ptr::addr_of!((*hdr).hdr_len)) } >> 4) * 4;
            raw_offset = offset + len as usize;
            if data + raw_offset > data_end {
                return Err(xdp_action::XDP_PASS);
            }
            src_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*hdr).src_port)) });
            dst_port = u16::from_be(unsafe { ptr::read_unaligned(ptr::addr_of!((*hdr).dst_port)) });
        }
        _ => return Err(xdp_action::XDP_PASS),
    }
    Ok((src_port, dst_port, raw_offset))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
