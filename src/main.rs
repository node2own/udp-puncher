use anyhow::Result;
use udp_puncher::{udp_puncher, Role};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    udp_puncher(Role::Listener).await
}
