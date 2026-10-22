# Ssocks

Experimental, unaudited Shadowsocks libraries for Gleam.

## Installation

```sh
git clone https://github.com/P4suta/ssocks.git
cd ssocks
mise trust
mise install
mise run deps
```

## Usage

```gleam
import gleam/io
import ssocks/url

pub fn main() {
  let assert Ok(config) =
    url.parse("ss://YWVzLTI1Ni1nY206cGFzc3dk@example.com:8388#Tokyo")
  io.println(url.redacted(config))
}
```

## Documentation

[Read the documentation](docs/README.md).

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the [Massachusetts Institute of Technology (MIT) license](LICENSE-MIT), at your option.
You license each contribution you submit under the same two licenses, without other terms, unless you state otherwise.
