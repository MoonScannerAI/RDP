//! DirectDeskClient — connect, decode, display, capture input. (M1 fills this in.)

fn main() -> anyhow::Result<()> {
    let _guard = directdesk_shared::logging::init("client", directdesk_shared::logging::default_log_dir());
    tracing::info!("DirectDeskClient {} starting", env!("CARGO_PKG_VERSION"));
    println!("DirectDeskClient scaffold — implementation lands in M1.");
    Ok(())
}
