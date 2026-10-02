# crowsi-independent-verifier

Check an operation result against evidence obtained independently of its execution receipt.

## What you can do

- Match identity, scope and expected read-back evidence.
- Return verification results without executing the operation.

## Current scope

The caller supplies trusted read-back inputs. Missing evidence remains unresolved rather than being assumed successful.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
