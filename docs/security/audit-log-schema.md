# Audit Log Schema

Audit details are defined in [audit metadata](../reference/audit-metadata.md).

## Required Properties

- actor
- action
- resource type
- resource ID
- request ID or trace ID when available
- authentication context
- state transition metadata
- redacted secret handling
- failure result code for rejected API requests

## Retention And Query

The service supports audit query filters, pagination, sorting, and retention
pruning. Production deployments must define retention duration and export
requirements.

## Gaps

- tamper-evident storage plan
- SIEM export schema and detection examples
- evidence pack for policy changes

