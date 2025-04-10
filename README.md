# Sigma to ElastAlert Converter

A Python tool that converts [Sigma](https://github.com/SigmaHQ/sigma) rules to [ElastAlert 2](https://github.com/jertel/elastalert2) format for use in security monitoring systems.

## Overview

This tool allows security teams to leverage the extensive library of Sigma detection rules within ElastAlert alerting systems. It converts the Sigma YAML format into ElastAlert rule configurations, preserving metadata and translating detection logic into Elasticsearch queries.

## Status

⚠️ **Under Construction** ⚠️

This converter is still in development and has not been tested against all Sigma rules. Some complex detection patterns may not convert correctly. Use with caution and verify rule conversions before deploying to production environments.

## Features

- Converts Sigma detection logic to Elasticsearch query DSL
- Preserves rule metadata (title, description, tags, etc.)
- Handles field mappings between Sigma fields and Elastic Common Schema
- Supports both individual file and batch directory conversion
- Interactive and command-line modes

## Usage

### Single File Conversion

```bash
python sigma_to_elastalert.py -f path/to/sigma_rule.yml -o output_rule.yaml
```

### Directory Converstion

```bash
python sigma_to_elastalert.py -d path/to/sigma_rules_dir -o path/to/output_dir
```

### Output Location

```|~/elastalert_rules/```
