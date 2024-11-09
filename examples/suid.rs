#[macro_use]
extern crate log;
extern crate simple_logger;

// Try running this example as root, or using setcap to give it the necessary capabilities!
// ... or do something else to give it suid/sgid permissions I guess?

fn main() {
    simple_logger::SimpleLogger::new()
        .init()
        .expect("unable to initialize logger");

    uid_euid("[1]");

    spawn("/usr/bin/id");

    println!("RunningAs: {:#?}", karen::check());

    karen::builder()
        .as_user(1001)
        .as_group(1001)
        .set_ids()
        .unwrap();

    uid_euid("[2]");

    spawn("/usr/bin/id");

    println!("RunningAs: {:#?}", karen::check());
}

fn uid_euid(nth: &str) {
    let euid = unsafe { libc::geteuid() };
    let uid = unsafe { libc::getuid() };
    info!("{} uid: {}; euid: {};", nth, uid, euid);
}

fn spawn(cmd: &str) {
    let mut child = std::process::Command::new(cmd)
        .spawn()
        .expect("unable to start child");

    let _ecode = child.wait().expect("failed to wait on child");
}
