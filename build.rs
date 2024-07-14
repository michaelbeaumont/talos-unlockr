fn main() -> Result<(), Box<dyn std::error::Error>> {
    let no_includes: [&str; 0] = [];
    tonic_build::configure()
        .build_client(false)
        .compile(&["proto/kms.proto"], &no_includes)?;
    Ok(())
}
