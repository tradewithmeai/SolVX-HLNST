# SolVX Home Lab Network & Security Toolkit

A **local-first** network monitoring and security analysis tool for home labs and small networks.

## Features

- 📦 **PCAP Analysis**: Import and analyze packet capture files
- 🔍 **Device Discovery**: Automatic device inventory with fingerprinting
- 🛡️ **Threat Detection**:
  - Rogue device detection
  - ARP spoofing / MITM detection
  - DNS leak detection
- 📊 **Threat Scoring**: Risk assessment for devices and network
- 🖥️ **Multiple Interfaces**: CLI, REST API, and Web GUI
- 🔌 **Plugin System**: Extensible detection and output plugins
- 🧪 **Virtual Lab**: Generate synthetic PCAPs for testing

## Philosophy

- **Local by default**: No cloud, no "phone home"
- **Privacy-first**: All data stays on your machine
- **Scriptable**: Everything accessible via CLI and API
- **Modular**: Clean architecture, easy to extend

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/SolVX-HLNST.git
cd SolVX-HLNST

# Install dependencies
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

### 1. Initialize Database

```bash
solvx db init
```

### 2. Import a PCAP

```bash
solvx pcap import /path/to/capture.pcap
```

### 3. List Devices

```bash
solvx devices list
```

### 4. View Alerts

```bash
solvx alerts list
```

### 5. Start Web Interface

```bash
solvx api start
# Open http://localhost:8000 in your browser
```

## Configuration

Configuration is managed via:
- Environment variables (prefix: `SOLVX_`)
- Default values in code

View current configuration:
```bash
solvx config --show
```

Key configuration paths:
- Database: `~/.solvx/solvx.db`
- Logs: `~/.solvx/logs/`
- PCAPs: `~/.solvx/pcaps/`

## Project Structure

```
solvx_net/
├── core/           # Config, logging, database, models
├── pcap/           # PCAP parsing
├── capture/        # Live packet capture
├── analysis/       # Flow building and analysis
├── detections/     # Detection engines
├── fingerprinting/ # Device fingerprinting
├── api/            # FastAPI server
├── cli/            # CLI commands
├── web/            # Web frontend
└── plugins/        # Plugin system
```

## Development Phases

- ✅ **Phase 1**: Core infrastructure (config, logging, DB, CLI)
- ✅ **Phase 2**: PCAP import and flow analysis
- ✅ **Phase 3**: Device fingerprinting
- ✅ **Phase 4**: Detection engines (rogue devices, ARP spoofing, DNS leaks)
- ✅ **Phase 5**: Threat scoring and risk assessment
- ✅ **Phase 6**: REST API with FastAPI (Web UI guide provided)
- 📋 **Phase 7**: Live packet capture
- 📋 **Phase 8**: Plugin system
- 📋 **Phase 9**: Virtual lab / PCAP generator

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or PR.

## Acknowledgments

Built with:
- [Scapy](https://scapy.net/) - Packet manipulation
- [FastAPI](https://fastapi.tiangolo.com/) - Web API
- [Typer](https://typer.tiangolo.com/) - CLI
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
