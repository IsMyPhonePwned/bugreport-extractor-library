<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">Bugreport Extractor Library</h2>

# bugreport-extractor-library: Read and extract data from Android BugReport in pure Rust

<div align="center">

![Powered By: IsMyPhonePwned](https://img.shields.io/badge/androguard-green?style=for-the-badge&label=Powered%20by&link=https%3A%2F%2Fgithub.com%2Fandroguard)
![Sponsor](https://img.shields.io/badge/sponsor-nlnet-blue?style=for-the-badge&link=https%3A%2F%2Fnlnet.nl%2F)

</div>

This Rust project provides a framework for parsing [Android Bugreport](https://source.android.com/docs/core/tests/debug/read-bug-reports) using a modular and extensible parser system. It is designed for speed and efficiency by using memory-mapped file I/O and parallel processing with Rayon, allowing multiple parsers to run concurrently on the same data source.

## Key Features

- Memory-Mapped Files: Uses memmap2 to handle large files (200MB+) with minimal RAM usage.

- Concurrent Parsing: Uses rayon to run multiple parsers in parallel, taking advantage of multi-core processors.

- Extensible Architecture: Easily add new parsers by implementing a simple Parser trait.


## Build

Build the project:

```
cargo build --release
```

## Parsers (WIP)

### Header
### Memory

## Usage

Run multiple parsers from the command line:

```
cargo run --release -- --file-path=dumpstate.txt --parser-type header --parser-type memory
```

it will allow the header and the memory parse to run.

### Add new parser


The process is the same as before, as the core trait has not changed.

Create a new file in the src/parsers/ directory (e.g., src/parsers/json_lines_parser.rs).

Define your parser struct (e.g., pub struct JsonLinesParser;). Your struct must be Send and Sync (which is usually the default if it doesn't contain thread-unsafe types like Rc or RefCell).

Implement the Parser trait for your struct.

Expose your new parser in src/parsers/mod.rs.

Add your parser to the ParserType enum in src/parsers/mod.rs.

Update the get_parser factory function in src/parsers/mod.rs to include your new parser.

## License

Distributed under the [Apache License, Version 2.0](LICENSE).