use std::process::exit;
use std::thread::{spawn, JoinHandle};
use anyhow::{anyhow, Result};
use ctrlc::set_handler;
use log::{error, info};
use udp_puncher::{udp_puncher, Role};

fn main() {
    env_logger::init();

    if let Err(error) = app() {
        error!("Error: {error}");
    } else {
        error!("Exit");
    }
    exit(1); // This kills all threads
}

fn app() -> Result<()> {

    set_handler(move || {
        info!("Received Ctrl+C!");
        exit(1); // This kills all threads
    })?;

    let mut remotes = vec![];
    for arg in std::env::args().skip(1) {
        remotes.push(arg);
    }

    let listener_handle = panic_on_exit("Listener",|| udp_puncher(Role::Listener));
    let initiator_handle = panic_on_exit("Initiator", || udp_puncher(Role::Initiator(remotes)));
    listener_handle.join().map_err(|e| anyhow!("{e:?}"))?;
    initiator_handle.join().map_err(|e| anyhow!("{e:?}"))?;
    Ok(())
}

fn panic_on_exit<F, T>(label: &str, f: F) -> JoinHandle<T>
where
F: FnOnce() -> Result<T>,
F: Send + 'static,
T: Send + 'static
{
    let label = label.to_owned();
    spawn(move || {
        if let Err(e) = f() {
            error!("Error in {}: {}", label, e);
            exit(1); // This kills all threads
        } else {
            error!("Exit {}", label);
            exit(1); // This kills all threads
        }
    })
}
