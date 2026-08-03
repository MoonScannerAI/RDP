//! DirectDeskService — supervised autostart + privileged ops. (M3 fills this in.)

fn main() -> anyhow::Result<()> {
    let _guard = directdesk_shared::logging::init("service", directdesk_shared::logging::default_log_dir());
    tracing::info!("DirectDeskService {} starting", env!("CARGO_PKG_VERSION"));
    println!("DirectDeskService scaffold — implementation lands in M3.");
    Ok(())
}
