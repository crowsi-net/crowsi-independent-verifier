# Using crowsi-independent-verifier

Check an operation result against evidence obtained independently of its execution receipt.

## Before you start

The caller supplies trusted read-back inputs. Missing evidence remains unresolved rather than being assumed successful.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Match identity, scope and expected read-back evidence.
- Return verification results without executing the operation.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
