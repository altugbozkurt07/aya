use std::{fs::File, net::TcpListener, os::unix::process::CommandExt};

use aya::{programs::Lsm, util::KernelVersion, Btf, Ebpf};
use log::debug;

use std::{
    process::{exit, Command},
    thread::sleep,
    time::Duration,
    path::Path,
};

use nix::{
    sys::wait::waitpid,
    unistd::{fork, ForkResult},
};

use cgroups_rs::*;
use cgroups_rs::cgroup_builder::*;


#[test]
fn lsm_cgroup() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 0, 0) {
        eprintln!("skipping lsm_cgroup test on kernel {kernel_version:?}");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog: &mut Lsm = bpf.program_mut("test_lsmcgroup").unwrap().try_into().unwrap();
    let btf = Btf::from_sys_fs().expect("could not get btf from sys");
    if let Err(err) = prog.load("task_setnice", &btf) {
        panic!("{err}");
    }


    let hier = cgroups_rs::hierarchies::auto();

    let cg: Cgroup = CgroupBuilder::new("lsm_cgroup_test")
        .build(hier)
        .expect("could not create cgroup");


    eprintln!("{:?}", Path::new(".").join("/sys/fs/cgroup/").join(cg.path()).to_str());

    let p = prog.attach(
        Some(File::open(Path::new(".").join("/sys/fs/cgroup/").join(cg.path())).unwrap()),
    )
    .unwrap();

  

    unsafe {
        match fork().expect("Failed to fork process") {
            ForkResult::Parent { child } => {
                // Do not forget to wait for the fork in order to prevent it from becoming a zombie!!!
                waitpid(Some(child), None).unwrap();
               
                cg.add_task(CgroupPid::from(child.as_raw() as u64));
                
                // You have 120 seconds to kill the process :)
                sleep(Duration::from_secs(120));

                cg.delete();
            }
    
            ForkResult::Child => {
                // replace with your executable
                // if let err = Command::new("/usr/bin/renice").args(["2", "-p", "8307"]).exec(){
                //     panic!("{err}");
                // }

                let listener = TcpListener::bind("127.0.0.1:12345").expect("could not bind socket");

                println!("now listening!");
                exit(0);
            }
        }
    }
    


}