![kraken](assets/kraken-banner_alpha_small.png)

---

# :octopus: The kraken-project :octopus:

[![LICENSE](https://img.shields.io/github/license/myOmikron/kraken-project?color=blue)](LICENSE)
[![dependency status](https://deps.rs/repo/github/myOmikron/kraken-project/status.svg)](https://deps.rs/repo/github/myOmikron/kraken-project)
[![backend ci](https://img.shields.io/github/actions/workflow/status/myOmikron/kraken-project/linux.yml?label=Backend)](https://github.com/myOmikron/kraken-project/actions/workflows/linux.yml)
[![frontend ci](https://img.shields.io/github/actions/workflow/status/myOmikron/kraken-project/frontend.yml?label=Frontend)](https://github.com/myOmikron/kraken-project/actions/workflows/frontend.yml)

The aim of this project is to create a fast, scalable pentesting platform.

It integrates existing tools as well as provides own implementations
for some attacks / reconnaissance work.

️:warning: **Caution**:

Please note that this project is under heavy development.
Expect breaking changes every once in a while.

## Single user

If you don't want to have the whole platform deployed, you can just execute `leech` on its own.

With the subcommand `execute`, you can start and configure the modules as they were normal cli utilities.

## Compile on debian

```bash
# Protobuf compiler and prebuilt proto files
apt install protobuf-compiler libprotoc-dev
```

## Contact

You want to discuss something? Get in touch with us in our [matrix
room](https://matrix.to/#/#kraken:matrix.hopfenspace.org).
