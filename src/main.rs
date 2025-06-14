use anyhow::Result;
use udp_puncher::udp_puncher;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    udp_puncher().await
}
