# ja-tools

A high-level implementation of `ClienHelloOverride` from [patched rustls](https://github.com/XOR-op/rustls.delta), as
well as JA3/JA4 support.

## What This Crate Does

- Allow modifying `ClientHello` fingerprints of all TLS requests initiated by `rustls`.
- Import fingerprint from a JA3-full string and check its JA3/JA4 fingerprints.
- Utilities for creating some extensions easily, e.g. grease ECH.

## Version Support
We use the forked version of rustls with necessary modifications. Every `rustls` version has a corresponding branch in the
forked repository. See the next section for more details.

- `rustls@0.23.12`: 'v0.23.12'

## How to Use

Because this crate relies on the patched `rustls`, it's impossible to directly use it from crates.io.
Instead, you need to use it by adding the following to your `Cargo.toml`:

```toml
ja-tools = { git = "https://github.com/XOR-op/ja-tools.git", branch = "main" }

```

and add the following to your root `Cargo.toml` of the workspace (if you have only one `Cargo.toml` file, add there):

```toml
[patch.crates-io]
rustls = { git = "https://github.com/XOR-op/rustls.delta.git", branch = "v0.23.12" }
```

Adding these will resolve all the same version `rustls` in the direct or indirect dependencies to the patched crate.
If a different version of `rustls` is used by one dependency, this crate will not work on that particular dependency.

[^1]: [Overriding Dependencies from Cargo Book](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html)

## License

This project is licensed under the [MIT License](LICENSE).
