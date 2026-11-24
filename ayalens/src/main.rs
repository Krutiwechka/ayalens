use std::{collections::HashMap, net::Ipv4Addr, sync::{Arc, Mutex}, time::Duration};

use anyhow::Context as _;
use aya::{maps::PerCpuHashMap, programs::{Xdp, XdpMode}};
use ayalens_common::{FlowInfo, FlowTuple};
use clap::Parser;
#[rustfmt::skip]
use log::debug;
use tokio::{signal, time::sleep};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ayalens"
    )))?;
    
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("ayalens").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?; 
    let result: Arc<Mutex<HashMap<FlowTuple, FlowInfo>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let result_shared = Arc::clone(&result);
    tokio::task::spawn(async move {
        let mut flows:  PerCpuHashMap<_, FlowTuple, FlowInfo> = ebpf.map_mut("LENS").expect("Map is created in eBPF side").try_into().expect("LENS must be a PerCpuHashMap");
        loop {
            for cf in flows.iter() {
                let (flow, per_cpu) = cf.expect("Iterator from map");
                let (mut pkts, mut bytes) = (0u64, 0u64);
                for f in per_cpu.iter() {
                    pkts += f.pkts;
                    bytes += f.bytes;
                }
                let mut res = result_shared.lock().expect("Shared map");
                res.entry(flow).and_modify(|flow_info| { flow_info.bytes += bytes; flow_info.pkts += pkts;}).or_insert(FlowInfo {bytes, pkts});
            } 
            let flow_tuples: Vec<FlowTuple> = flows.keys().filter_map(|f| f.ok()).collect();
            for f in flow_tuples {
                let _ = flows.remove(&f);
            }

            sleep(Duration::from_secs(1)).await;
        }
    });
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    let res = result.lock().expect("Shared map");
    let mut stats :Vec<_> = res.iter().collect();
    stats.sort_by(|flow1, flow2| {flow2.1.bytes.cmp(&flow1.1.bytes)}); 
    for(flow_tuple, flow_info) in stats{
        println!("[{}]: {}:{} -> {}:{}\t{} packets, {} bytes", flow_tuple.protocol, Ipv4Addr::from(flow_tuple.src_addr), flow_tuple.src_port, Ipv4Addr::from(flow_tuple.dst_addr), flow_tuple.dst_port, flow_info.pkts, flow_info.bytes);
    } 

    Ok(())
}
