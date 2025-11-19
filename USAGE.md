# SolVX Usage Guide

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/SolVX-HLNST.git
cd SolVX-HLNST

# Install package
pip install -e .
```

## Quick Start

### 1. Initialize Database

```bash
solvx db init
```

### 2. Import PCAP File

```bash
solvx pcap import /path/to/your/capture.pcap
```

This will:
- Parse the PCAP file
- Build network flows
- Discover and fingerprint devices automatically
- Store everything in the database

### 3. View Discovered Devices

```bash
# List all devices
solvx devices list

# Show detailed device info
solvx devices info 1
```

### 4. Manage Devices

```bash
# Set trust level
solvx devices trust 1 trusted

# Add tags
solvx devices tag 1 "IoT"
solvx devices tag 1 "camera"

# Re-fingerprint devices
solvx devices fingerprint
```

## Common Workflows

### Analyzing a New Capture

```bash
# Import the PCAP
solvx pcap import capture.pcap --notes "Weekend traffic"

# List captures
solvx pcap list

# View capture details
solvx pcap info 1

# List discovered devices
solvx devices list
```

### Device Management

```bash
# List only trusted devices
solvx devices list --trust trusted

# Fingerprint specific device
solvx devices fingerprint --device 5

# Mark rogue device as blocked
solvx devices trust 7 blocked
```

### Database Management

```bash
# Check database status
solvx db status

# Reset database (WARNING: deletes all data)
solvx db drop --yes
solvx db init
```

## Configuration

Configuration is managed via environment variables with the `SOLVX_` prefix:

```bash
# Set log level
export SOLVX_LOG_LEVEL=DEBUG

# Set database location
export SOLVX_DATABASE__URL=sqlite:////custom/path/solvx.db

# Set allowed DNS servers
export SOLVX_DETECTION__ALLOWED_DNS_SERVERS='["192.168.1.1", "1.1.1.1"]'
```

Or view current configuration:

```bash
solvx config --show
```

## Current Features

### Phase 1-3 (Completed)
- ✅ PCAP file import and parsing
- ✅ Network flow aggregation
- ✅ Automatic device discovery
- ✅ Vendor identification (OUI lookup)
- ✅ Device fingerprinting (OS and type detection)
- ✅ Device inventory management
- ✅ Trust level management
- ✅ Device tagging

### Coming Soon (Phase 4-6)
- 🚧 Rogue device detection
- 🚧 ARP spoofing detection
- 🚧 DNS leak detection
- 🚧 Threat scoring
- 🚧 REST API server
- 🚧 Web dashboard
- 🚧 Real-time capture
- 🚧 Plugin system

## Troubleshooting

### Database Locked Error

If you see a database locked error, ensure no other solvx process is running:

```bash
# Check for running processes
ps aux | grep solvx

# Kill if needed
pkill -f solvx
```

### PCAP Permission Denied

For live capture (future feature), you'll need root permissions:

```bash
sudo solvx capture live --iface eth0
```

### Low Memory with Large PCAPs

For very large PCAP files, consider:
- Splitting the PCAP into smaller chunks
- Increasing available memory
- Processing on a more powerful machine

## Examples

### Example 1: Home Network Audit

```bash
# Initialize
solvx db init

# Import capture
solvx pcap import home_network_24h.pcap --notes "24 hour home network capture"

# Review devices
solvx devices list

# Mark known devices as trusted
solvx devices trust 1 trusted  # Router
solvx devices trust 2 trusted  # Laptop
solvx devices trust 3 trusted  # Phone

# Mark guest devices
solvx devices trust 4 guest    # Guest phone

# Tag IoT devices
solvx devices tag 5 "IoT"
solvx devices tag 5 "camera"
```

### Example 2: Multiple Captures

```bash
# Import multiple captures
solvx pcap import morning.pcap --notes "Morning traffic"
solvx pcap import afternoon.pcap --notes "Afternoon traffic"
solvx pcap import evening.pcap --notes "Evening traffic"

# View all captures
solvx pcap list

# Devices will be merged across captures
solvx devices list

# View specific capture
solvx pcap info 2
```

## Tips

1. **Regular Imports**: Import captures regularly to build a complete device inventory
2. **Tag Devices**: Use tags to organize devices by function or location
3. **Trust Levels**: Set trust levels to prepare for future threat detection
4. **Fingerprinting**: Run fingerprinting after importing captures to identify devices
5. **Backup**: Periodically backup your `~/.solvx/solvx.db` file

## Next Steps

After familiarizing yourself with the basics:
1. Try importing your own PCAP captures
2. Set up proper trust levels for your network
3. Explore the device fingerprinting results
4. Wait for Phase 4+ features (detection engines, API, web UI)
