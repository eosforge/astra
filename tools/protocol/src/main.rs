//! Generate stable MessageIDs using the existing pinned protocol tools.
//!
//! Stage outputs privately. `--check` only compares; update mode writes only after all generation succeeds.

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use prost::Message;

mod ids;

/// Owns generated regular files; Drop removes them individually without recursive directory deletion.
struct Scratch(PathBuf);

impl Scratch {
    /// Creates an exclusive staging directory below the repository build tree, propagating I/O failures.
    fn create(root: &Path) -> io::Result<Self> {
        let parent = root.join("build/proto");
        fs::create_dir_all(&parent)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_nanos();
        let path = parent.join(format!("generate-{}-{nonce}", std::process::id()));
        // Exclusive creation prevents cleanup from touching another invocation's output.
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    /// Attempts to remove owned regular files and the empty directory without following other entry types.
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.0) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_file()) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        let _ = fs::remove_dir(&self.0);
    }
}

/// Parses the sole check flag and locates the repository from this package's manifest.
fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let check = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "--check" => true,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "usage: generate-proto [--check]").into()),
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("missing repository root"))?;
    let scratch = Scratch::create(root)?;
    let proto_root = root.join("proto");
    let mut schemas: Vec<_> = fs::read_dir(&proto_root)?
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .map(|entry| entry.path())
        // The registry covers astra/orbit/comet only. Build/Go generators own Pulsar/Polaris bindings.
        .filter(|path| {
            path.extension().is_some_and(|extension| extension == "proto")
                && path.file_name().is_none_or(|name| name != "pulsar.proto" && name != "polaris.proto")
        })
        .collect();
    schemas.sort();
    if schemas.is_empty() {
        return Err(io::Error::other("no protocol schemas").into());
    }

    // An explicit tool path applies only to this invocation, without changing user configuration.
    let executable = |name: &str| if cfg!(windows) { format!("{name}.exe") } else { name.to_owned() };
    let protoc = env::var_os("PROTOC").map(PathBuf::from).unwrap_or_else(|| {
        env::var_os("ASTRA_CACHE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("build"))
            .join("tools/protoc/36.1/bin")
            .join(executable("protoc"))
    });
    require_version(&protoc, "libprotoc 36.1")?;

    // Descriptors supply stable IDs; tools/generate.py owns Go bindings. Legacy Rust services remain retired.
    run(Command::new(&protoc)
        .arg(format!("--descriptor_set_out={}", scratch.0.join("descriptor.pb").display()))
        .arg("--include_imports")
        .arg("-I")
        .arg(&proto_root)
        .args(&schemas))?;
    let registry = generate_ids(&scratch.0, &proto_root)?;

    // Compare all outputs before writing. Descriptors remain temporary; only message-ids.lock is published.
    let mut outputs = BTreeMap::new();
    outputs.insert(proto_root.join("message-ids.lock"), registry.into_bytes());
    let stale: Vec<_> = outputs
        .iter()
        .filter(|(path, bytes)| fs::read(path).as_deref().ok() != Some(bytes.as_slice()))
        .collect();
    if check && !stale.is_empty() {
        for (path, _) in &stale {
            eprintln!("stale: {}", path.display());
        }
        return Err(io::Error::other("generated protocol differs; run tools/generate-proto").into());
    }
    for (path, bytes) in stale {
        fs::create_dir_all(path.parent().ok_or_else(|| io::Error::other("missing output parent"))?)?;
        if path == &proto_root.join("message-ids.lock") {
            ids::store(path, &fs::read_to_string(path)?, std::str::from_utf8(bytes)?, true)?;
        } else {
            fs::write(path, bytes)?;
        }
        println!("generated: {}", path.display());
    }
    println!("protocol {}", if check { "is current" } else { "generated" });
    Ok(())
}

/// Propagates tool failure without downloading a replacement or silently changing versions.
fn run(command: &mut Command) -> io::Result<()> {
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other(format!("protocol tool exited with {status}")));
    }
    Ok(())
}

/// Requires the pinned generator version, independently of local PATH ordering.
fn require_version(tool: &Path, expected: &str) -> io::Result<()> {
    let output = Command::new(tool)
        .arg("--version")
        .output()
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}; see proto/README.md", tool.display())))?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != expected {
        return Err(io::Error::other(format!("expected {expected}")));
    }
    Ok(())
}

/// Assigns stable IDs to top-level messages only, using one shared registry.
fn generate_ids(output: &Path, proto_root: &Path) -> Result<String, Box<dyn Error>> {
    let descriptor = prost_types::FileDescriptorSet::decode(fs::read(output.join("descriptor.pb"))?.as_slice())?;
    let mut messages = BTreeMap::new();
    for file in descriptor
        .file
        .iter()
        .filter(|file| file.name.as_ref().is_some_and(|name| !name.starts_with("google/")))
    {
        let package = file.package.as_deref().ok_or_else(|| io::Error::other("protocol package is required"))?;
        // Validate package ownership even when a schema has no messages.
        if !matches!(package, "proto.astra.v1" | "proto.orbit.v1" | "proto.comet.v1") {
            return Err(io::Error::other("unsupported protocol package").into());
        }
        for message in &file.message_type {
            let name = message.name.as_deref().ok_or_else(|| io::Error::other("unnamed message"))?;
            messages.insert(format!("{package}.{name}"), name.to_owned());
        }
    }
    let previous = fs::read_to_string(proto_root.join("message-ids.lock"))?;
    let ids = ids::assign(&previous, messages.keys().cloned())?;
    let mut registry = String::from("# Automatically assigned MessageIDs. Commit this file with proto schemas. Never reuse an ID.\n");
    for (id, name) in &ids {
        registry.push_str(&format!("{id}\t{name}\n"));
    }
    let active: Vec<_> = ids
        .iter()
        .filter_map(|(id, full_name)| messages.get(full_name).map(|name| (*id, name)))
        .collect();

    let mut go = String::from(
        "// Code generated by astra-protocol-generator from proto/*.proto and message-ids.lock. DO NOT EDIT.\npackage wire\nimport \"google.golang.org/protobuf/proto\"\ntype MessageID uint16\nconst (\n",
    );
    for (id, name) in &active {
        go.push_str(&format!("ID{name} MessageID = {id}\n"));
    }
    go.push_str(")\nfunc NewMessage(id MessageID) proto.Message { switch id {\n");
    for (_, name) in &active {
        go.push_str(&format!("case ID{name}: return &{name}{{}}\n"));
    }
    go.push_str("default: return nil } }\nfunc IDOf(message proto.Message) (MessageID, bool) { switch message.(type) {\n");
    for (_, name) in &active {
        go.push_str(&format!("case *{name}: return ID{name}, true\n"));
    }
    go.push_str("default: return 0, false } }\n");
    fs::write(output.join("message_ids.go"), go)?;
    Ok(registry)
}
