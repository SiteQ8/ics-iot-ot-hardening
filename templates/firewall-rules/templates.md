# Firewall Configuration Templates

This directory contains vendor-neutral and vendor-specific firewall rule templates to implement the network segmentation and boundary protection described in the ICS hardening framework.

## Files

- purdue-model.yaml
  - YAML template defining zones and conduits according to the Purdue model.
  - Used by `firewall-generator.py` to generate rule sets.

- palo-alto-example.conf
  - Palo Alto Networks firewall rules in configuration CLI format.
  - Includes sample policies for Enterprise to DMZ, DMZ to Operations, and ICS zones.

- checkpoint-example.fws
  - Check Point firewall policy script for ICS segmentation.
  - Demonstrates best practices for rule naming, logging, and default-deny policies.

- fortinet-example.conf
  - FortiGate firewall configuration snippet.
  - Illustrates policy definitions, address objects, and logging settings.

- aws-nacl-example.json
  - AWS Network ACL JSON template for cloud-based ICS network segmentation.
  - Defines inbound/outbound rules and subnet associations.

- gcp-fw-example.yaml
  - Google Cloud Firewall rule template.
  - Uses Terraform syntax to define VPC firewall rules aligned with ICS zones.

## Usage

1. Review and customize the `purdue-model.yaml` to match your network zones.
2. Run `firewall-generator.py`:
   ```bash
   python3 firewall-generator.py purdue-model.yaml --format palo_alto -o palo.conf
   ```
3. Import the generated configuration into your firewall management console.
