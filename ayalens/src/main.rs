use std::{
    collections::HashMap, net::Ipv4Addr, os::fd::{AsFd, AsRawFd}, ptr::addr_of_mut, sync::{Arc, Mutex}, time::Duration,
};

use anyhow::Context as _;
use aya::{
    maps::{MapData, PerCpuArray, loaded_maps}, programs::{Xdp, XdpMode},
};
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
    
    let result: Arc<Mutex<HashMap<FlowTuple, FlowInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let result_shared = Arc::clone(&result);
    let undetected: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.map("UNDETECTED").expect("no UNDETECTED map")).expect("UNDETECTED map opening error");
    tokio::task::spawn(async move {
        let id = loaded_maps().filter_map(Result::ok).find(|i| i.name_as_str() == Some("LENS")).map(|i| i.id()).expect("no map LENS");
        let data = MapData::from_id(id).expect("LENS id error");

        let map_fd = data.fd().as_fd().as_raw_fd();
        let ncpu = aya::util::nr_cpus().expect("nr_cpus");
        let mut keys = vec![unsafe { std::mem::zeroed::<FlowTuple>()}; BATCH];
        let mut values = vec![unsafe { std::mem::zeroed::<FlowInfo>()}; BATCH * ncpu];
        let mut batch_pos = 0u32;
        let mut attr = BatchAttr {
            in_batch: 0, 
            out_batch: addr_of_mut!(batch_pos) as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count: BATCH as u32,
            map_fd: map_fd as u32,
            elem_flags: 0,
            flags: 0,
        };
        let mut restart = true;
        loop {
            sleep(Duration::from_secs(1)).await;

            attr.count = BATCH as u32;
            attr.in_batch = if restart { 0 } else {addr_of_mut!(batch_pos) as u64};
            restart = false;
            let ret = unsafe {
            libc::syscall(libc::SYS_bpf, BPF_MAP_LOOKUP_AND_DELETE, &mut attr as *mut BatchAttr, std::mem::size_of::<BatchAttr>())};
            let n = attr.count as usize;
            let mut agg: HashMap<FlowTuple, (u64, u64)> = HashMap::with_capacity(n);
            for i in 0..n {
                let mut pkts = 0u64;
                let mut bytes = 0u64;
                for slot in &values[i * ncpu .. (i + 1) * ncpu] {
                    pkts += slot.pkts;
                    bytes += slot.bytes;
                }
                let e = agg.entry(keys[i]).or_insert((0, 0));
                e.0 += pkts;
                e.1 += bytes;

            }
            let mut res = result_shared.lock().expect("Shared map");
            
                for (k, (p, b)) in agg {
                    res.entry(k)
                        .and_modify(|fi| { fi.pkts += p; fi.bytes += b; })
                        .or_insert(FlowInfo { pkts: p, bytes: b });
                }
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    eprintln!("LENS batch: {err}");
                    break;
                    
                }
                restart = true;
            }
        }
    });
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    let res = result.lock().expect("Shared map");
    let mut stats: Vec<_> = res.iter().collect();
    stats.sort_by(|flow1, flow2| flow2.1.bytes.cmp(&flow1.1.bytes));
    let mut pkts = 0u64;
    let mut bytes = 0u64;
    for (flow_tuple, flow_info) in stats.iter().take(10) {
        println!(
            "[{}]: {}:{} -> {}:{}\t{} packets, {} bytes",
            flow_tuple.protocol,
            Ipv4Addr::from(flow_tuple.src_addr),
            flow_tuple.src_port,
            Ipv4Addr::from(flow_tuple.dst_addr),
            flow_tuple.dst_port,
            flow_info.pkts,
            flow_info.bytes
        );
    }
    for (_, fi) in stats.iter() { pkts += fi.pkts; bytes += fi.bytes; } 
    println!("{pkts} packets, {bytes} bytes"); 
    let unk_p: u64 = undetected.get(&0, 0).expect("UNDETECTED map reading error").iter().sum();
    let unk_b: u64= undetected.get(&1, 0).expect("UNDETECTED map reading error").iter().sum();
    let frag_p: u64= undetected.get(&2, 0).expect("UNDETECTED map reading error").iter().sum();
    let frag_b: u64= undetected.get(&3, 0).expect("UNDETECTED map reading error").iter().sum();
    if unk_p > 0{
        println!("unknown: {unk_p} packets, {unk_b} bytes");
    }
    if frag_p > 0{
        println!("fragmented: {frag_p} packets, {frag_b} bytes");
    } 
    Ok(())
}
const BPF_MAP_LOOKUP_AND_DELETE: libc::c_long = 25;
const BATCH: usize = 16384;

#[repr(C)]
#[derive(Copy, Clone)]
struct BatchAttr{
    in_batch: u64,
    out_batch: u64,
    keys: u64, 
    values: u64, 
    count: u32, 
    map_fd: u32,
    elem_flags: u32,
    flags: u32,
}

unsafe impl aya::Pod for BatchAttr {}
