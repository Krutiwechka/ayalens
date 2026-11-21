#![no_std]
#![no_main]


use core::ptr;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use ayalens_common::{EthHdr, eth_type};
#[xdp]
pub fn ayalens(ctx: XdpContext) -> u32 {
     try_parse(&ctx) 
}

fn try_parse(ctx: &XdpContext) -> u32{
    let eth_type = match parse_eth(ctx){
        Ok(eth_type) => eth_type,
        Err(err) => return err,
    };
    match eth_type {
        eth_type::IPV4 => {
            info!(ctx, "[ETH] ipv4 packet");
        } 
        _ => info!(ctx, "[ETH] unknown packet") 
    };
    
    xdp_action::XDP_PASS
}

fn parse_eth(ctx: &XdpContext) -> Result<u16, u32>{
    let data = ctx.data();
    let data_end = ctx.data_end();
    let eth_end = data + size_of::<EthHdr>();
    if eth_end > data_end {
        return Err(xdp_action::XDP_PASS);
    }
    let eth_hdr = data as *const EthHdr;
    let eth_type = unsafe {ptr::read_unaligned(ptr::addr_of!((*eth_hdr).eth_type))};
    return Ok(eth_type);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
