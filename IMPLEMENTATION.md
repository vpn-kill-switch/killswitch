# Killswitch Rust Implementation

## Overview

This is a complete Rust rewrite of the killswitch VPN tool for macOS, following modern CLI architecture patterns and best practices.

## Architecture

The project follows a modular CLI architecture with clear separation of concerns:

```
src/
├── bin/
│   └── killswitch.rs         # Binary entry point
├── cli/                      # CLI layer (generic, reusable)
│   ├── actions/
│   │   ├── mod.rs           # Action enum definitions
│   │   └── run.rs           # Action execution logic
│   ├── commands/
│   │   └── mod.rs           # Clap CLI definitions
│   ├── dispatch/
│   │   └── mod.rs           # ArgMatches → Action conversion
│   ├── mod.rs               # Module exports
│   ├── start.rs             # Main orchestrator
│   └── telemetry.rs         # Logging/verbosity handling
├── killswitch/              # Domain logic (killswitch-specific)
│   ├── mod.rs              # Public API
│   ├── network.rs          # VPN interface detection
│   ├── pf.rs               # macOS pf firewall operations
│   └── rules.rs            # Firewall rules generation
└── lib.rs                  # Library entry point
```

## Data Flow

```
bin/killswitch.rs
    ↓
cli::start()
    ↓
┌─────────────────────────────────────────────┐
│ 1. commands::new().get_matches()            │  Parse CLI arguments
│    ↓                                         │
│ 2. telemetry::from(verbose_count)           │  Extract verbosity
│    ↓                                         │
│ 3. telemetry::init(level)                   │  Initialize logging
│    ↓                                         │
│ 4. dispatch::handler(&matches)              │  Convert to Action
│    ↓                                         │
│ 5. action.execute()                         │  Execute action
│    ↓                                         │
│ 6. killswitch::{enable,disable,status}()    │  Domain operations
└─────────────────────────────────────────────┘
```

## Features

### Core Functionality

- **Enable Kill Switch**: Block all non-VPN traffic using macOS pf firewall
- **Disable Kill Switch**: Remove firewall rules and restore normal traffic
- **Status Check**: Query current kill switch state
- **Print Rules**: Generate and display firewall rules without applying them

### Options

- `--ipv4 <IP>`: Specify VPN peer address (auto-detected if not provided)
- `--leak`: Allow ICMP (ping) and DNS requests outside the VPN
- `--local`: Allow local network traffic
- `--verbose`: Increase logging verbosity (-v: INFO, -vv: DEBUG, -vvv: TRACE)

### Firewall Rules

The kill switch implements a whitelist approach:

1. **Block all IPv6 traffic** (prevent IPv6 leaks)
2. **Allow VPN peer** (ensure VPN connection works)
3. **Allow loopback** (lo0 interface)
4. **Allow local networks** (optional, with --local)
5. **Allow DHCP** (UDP ports 67-68 for network configuration)
6. **Allow ICMP/DNS** (optional, with --leak)
7. **Block everything else** (default deny)

## Code Quality

### Linting

The project uses strict Clippy lints:

```toml
[lints.clippy]
pedantic = "deny"
all = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
indexing_slicing = "deny"
```

All lints pass with zero warnings.

### Testing

- **18 unit tests** covering:
  - Command parsing
  - Dispatch logic
  - Network address extraction
  - Firewall rule generation
  - CIDR conversion
  
All tests pass: `cargo test`

### Documentation

- All public functions have doc comments
- Functions returning `Result` have `# Errors` sections
- Clear inline comments where needed

## Dependencies

```toml
[dependencies]
anyhow = "1"                                          # Error handling
clap = { version = "4", features = ["string", "env"] }  # CLI parsing
tracing = "0.1"                                       # Structured logging
tracing-subscriber = { version = "0.3", features = ["env-filter"] }  # Log subscriber
libc = "0.2"                                          # Unix system calls (for root check)
```

## Usage Examples

### Basic Usage

```bash
# Show help
killswitch --help

# Enable kill switch (requires root)
sudo killswitch --enable

# Enable with options
sudo killswitch --enable --local --leak

# Check status
killswitch --status

# Disable kill switch
sudo killswitch --disable
```

### Print Rules (No Root Required)

```bash
# Show rules that would be applied
killswitch --print --ipv4 10.8.0.1

# Show rules with all options
killswitch --print --ipv4 10.8.0.1 --leak --local
```

### Verbose Output

```bash
# INFO level logging
sudo killswitch --enable -v

# DEBUG level logging
sudo killswitch --enable -vv

# TRACE level logging (everything)
sudo killswitch --enable -vvv
```

## Design Decisions

### 1. Modular Architecture

The CLI layer (`src/cli/`) is completely generic and reusable. Domain-specific logic lives in `src/killswitch/`. This makes it easy to:

- Test each component independently
- Add new commands without touching domain logic
- Reuse the CLI pattern in other projects

### 2. Action Enum

Actions are strongly typed:

```rust
pub enum Action {
    Enable { ipv4: Option<String>, leak: bool, local: bool },
    Disable,
    Status,
    Print { ipv4: Option<String>, leak: bool, local: bool },
}
```

This provides:
- Compile-time guarantees about valid actions
- Clear documentation of what's possible
- Easy refactoring and IDE support

### 3. Error Handling

Uses `anyhow::Result` throughout for ergonomic error handling:

- Context added at each layer
- Clear error messages
- No panics (enforced by Clippy)

### 4. Privilege Management

Root checking is centralized in `killswitch::check_root()`:

```rust
fn check_root() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!("This operation requires root privileges. Try: sudo killswitch");
    }
    Ok(())
}
```

Only operations that modify the firewall require root.

### 5. VPN Detection

Automatically detects VPN peer address by:

1. Parsing `ifconfig` output
2. Looking for VPN interfaces (utun, tun, ppp)
3. Extracting peer addresses from interface configuration
4. Falling back to manual specification with `--ipv4`

## macOS Specific Implementation

### pf (Packet Filter) Firewall

Uses macOS's built-in pf firewall:

- Rules stored in `/etc/pf.anchors/killswitch`
- Anchor referenced in `/etc/pf.conf`
- Managed via `pfctl` command

### Anchor Management

The implementation:

1. Creates anchor in pf.conf if not present
2. Writes rules to dedicated file
3. Loads anchor into pf
4. Enables pf if not already enabled
5. Gracefully handles existing configuration

## Build and Test

```bash
# Build
cargo build --release

# Run tests
cargo test

# Run clippy
cargo clippy -- -D warnings

# Run with verbose output
RUST_LOG=debug cargo run -- --print --ipv4 10.8.0.1
```

## Comparison with Go Version

| Aspect | Go Version | Rust Version |
|--------|-----------|--------------|
| Lines of Code | ~500 | ~1100 (with tests) |
| Architecture | Monolithic | Modular (CLI + Domain) |
| Error Handling | Manual checks | Result<T> pattern |
| Testing | Minimal | 18 unit tests |
| Linting | gofmt | Strict Clippy |
| Type Safety | Good | Excellent |
| Memory Safety | GC | Zero-cost abstractions |
| Binary Size | ~2MB | ~2MB |

## Future Enhancements

Possible additions:

1. **Configuration File**: Store preferences in `~/.killswitch/config.toml`
2. **Multiple VPN Profiles**: Support different rule sets
3. **DNS Leak Protection**: Enhanced DNS handling
4. **Notification System**: macOS notifications on state changes
5. **Auto-Enable**: Launch daemon to enable on VPN connect
6. **Web UI**: Optional local web interface
7. **Linux Support**: Add iptables backend

## Contributing

When adding features:

1. Add action variant in `cli/actions/mod.rs`
2. Add CLI argument in `cli/commands/mod.rs`
3. Add dispatch logic in `cli/dispatch/mod.rs`
4. Add execution logic in `cli/actions/run.rs`
5. Add domain logic in `killswitch/` modules
6. Add tests
7. Run `cargo clippy` and `cargo test`

## License

BSD-3-Clause (same as original)

## Credits

- Original Go version: Nicolas Embriz
- Rust rewrite: Following modern CLI architecture patterns
- Inspired by: [cron-when](https://github.com/nbari/cron-when) CLI architecture
