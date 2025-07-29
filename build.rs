fn main() -> Result<(), Box<dyn std::error::Error>> {
    let no_includes: [&str; 0] = [];
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&["proto/kms.proto"], &no_includes)?;
    Ok(())
}
