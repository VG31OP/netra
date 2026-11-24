use netra_core::NetraCore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    println!("Starting NETRA Desktop Application Engine...");

    let core = NetraCore::initialize()?;
    println!("Core initialized successfully in {} mode",
        if core.paths.is_portable { "Portable" } else { "Installed" });

    println!("Database: {}", core.paths.db_file.display());
    Ok(())
}
