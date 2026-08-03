//! DirectDeskHost — capture, encode, stream, inject. (M1 fills this in.)

fn main() -> anyhow::Result<()> {
    let _guard = directdesk_shared::logging::init("host", directdesk_shared::logging::default_log_dir());
    tracing::info!("DirectDeskHost {} starting", env!("CARGO_PKG_VERSION"));
    println!("DirectDeskHost scaffold — implementation lands in M1.");
    Ok(())
}
