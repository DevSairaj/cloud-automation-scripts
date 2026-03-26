# DR Orchestrator

A Python-based automation tool to manage **disaster recovery (DR) failover** for OCI instances by monitoring primary and standby systems and switching traffic via load balancer updates.

## Usage

Run the script:

```bash
python dr_orchestrator.py
```

## Configuration

1. Copy the example config:

```bash
cp config.example.json config.json
```

2. Update `config.json` with your actual OCI, instance, and email details.

## Features

* Automatic failover between primary and standby instances
* Supports multiple instance pairs
* Updates OCI load balancer backend sets dynamically
* Sends email alerts on failover activation and resolution
* Secure handling of credentials using encrypted values

## Notes

* Requires OCI Python SDK and proper IAM permissions
* Ensure standby instances are properly configured before use
