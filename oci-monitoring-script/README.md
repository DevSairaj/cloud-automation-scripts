# OCI Monitoring Script

A Python-based automation tool to monitor **OCI infrastructure, databases, and application-level metrics** for the **root compartment**, with Prometheus integration and intelligent alerting.

## Usage

Run the script:

```bash
python ocimonitor_root.py
```

Access Prometheus metrics:

```bash
http://localhost:8000
```

## Configuration

1. Copy the example config:

```bash
cp config.example.json config.json
```

2. Update `config.json` with your OCI, database, and email details.

## Features

* Monitors OCI compute instances (CPU, memory, disk, network, filesystem)
* Tracks OCI database metrics (CPU, storage, sessions)
* Tablespace monitoring with cooldown-based alerting
* Password expiry tracking for database users
* Schema-level session monitoring (total & active sessions)
* Load balancer and backend set health monitoring
* Config-driven exclusions (backend sets, schemas)
* Prometheus metrics export for Grafana integration
* Intelligent alerting with cooldown and auto-resolution emails
* Supports multiple databases and instances
* Designed for **root compartment-wide monitoring**

## Notes

* Requires OCI Python SDK, cx_Oracle, and Prometheus client
* Ensure database connectivity and correct credentials
* Script runs continuously and exposes metrics on port `8000`
