#!/usr/bin/env python3

"""
Sigma to ElastAlert Converter

This script converts Sigma rules to ElastAlert format for use in security monitoring.

Copyright (c) 2025 Andrew Arz. All rights reserved.
"""

import os
import sys
import yaml
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta

# Field mappings between Sigma fields and Elasticsearch fields
FIELD_MAPPINGS = {
    # File events
    'FileName': 'file.path',
    'TargetFilename': 'file.path',
    'Image': 'process.executable',
    'PreviousCreationUtcTime': 'file.created',
    'CreationUtcTime': 'file.created',
    'FileVersion': 'file.version',

    # Process fields
    'CommandLine': 'process.command_line',
    'ParentImage': 'process.parent.executable',
    'ParentCommandLine': 'process.parent.command_line',
    'ProcessId': 'process.pid',
    'ParentProcessId': 'process.parent.pid',
    'CurrentDirectory': 'process.working_directory',

    # Network fields - standard ECS naming
    'DestinationIp': 'destination.ip',
    'DestinationPort': 'destination.port',
    'DestinationHostname': 'destination.domain',
    'SourceIp': 'source.ip',
    'SourcePort': 'source.port',
    'SourceHostname': 'source.domain',
    'Protocol': 'network.protocol',

    # User fields
    'User': 'user.name',
    'SubjectUserName': 'user.name',
    'TargetUserName': 'user.target.name',
    'UserId': 'user.id',

    # Windows event fields
    'EventID': 'event.code',
    'EventType': 'event.type',
    'Channel': 'event.provider',
    'Provider': 'winlog.provider_name',

    # Registry fields
    'TargetObject': 'registry.path',
    'Details': 'registry.value',

    # Service fields
    'ServiceName': 'service.name',
    'ServiceFileName': 'service.executable',

    # Host fields
    'Hostname': 'host.name',
    'Computer': 'host.hostname',

    # DNS fields
    'QueryName': 'dns.question.name',
    'QueryType': 'dns.question.type',
    'QueryResults': 'dns.answers'
}

# Risk score mapping based on Sigma rule level
LEVEL_TO_PRIORITY = {
    'critical': 1,
    'high': 2,
    'medium': 3,
    'low': 4
}

class SigmaToElastAlert:
    def __init__(self, input_file, output_file=None, verbose=False):
        self.input_file = input_file
        self.output_file = output_file
        self.verbose = verbose
        self.rule_content = None
        self.elastalert_rule = {}

    def log(self, message):
        if self.verbose:
            print(f"[*] {message}")

    def load_rule(self):
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                self.rule_content = yaml.safe_load(f)
                self.log(f"Successfully loaded rule: {self.rule_content.get('title', 'Unnamed rule')}")
                return True
        except Exception as e:
            print(f"[!] Error loading rule file: {e}")
            return False

    def log_unmapped_fields(self, field_name):
        if not hasattr(self, 'unmapped_fields'):
            self.unmapped_fields = set()
        if '|' in field_name:
            base_field = field_name.split('|')[0]
            if base_field not in FIELD_MAPPINGS and base_field not in self.unmapped_fields:
                self.unmapped_fields.add(base_field)
                print(f"[INFO] Field not mapped to ECS (keeping original name): {base_field}")
        elif field_name not in FIELD_MAPPINGS and field_name not in self.unmapped_fields:
            self.unmapped_fields.add(field_name)
            print(f"[INFO] Field not mapped to ECS (keeping original name): {field_name}")

    def convert_field_to_es_filter(self, field_name, field_value):
        self.log_unmapped_fields(field_name)
        modifier = None
        if '|' in field_name:
            field_name, modifier = field_name.split('|', 1)
        es_field = FIELD_MAPPINGS.get(field_name, field_name)

        if modifier is not None and modifier.startswith('startswith'):
            if isinstance(field_value, list):
                terms = [{"prefix": {es_field: val}} for val in field_value]
                return {"bool": {"should": terms}}
            else:
                return {"prefix": {es_field: field_value}}
        elif modifier is not None and modifier.startswith('endswith'):
            if isinstance(field_value, list):
                terms = [{"wildcard": {es_field: f"*{val}"}} for val in field_value]
                return {"bool": {"should": terms}}
            else:
                return {"wildcard": {es_field: f"*{field_value}"}}
        elif modifier is not None and modifier.startswith('contains'):
            if modifier == 'contains|all':
                if isinstance(field_value, list):
                    terms = [{"wildcard": {es_field: f"*{val}*"}} for val in field_value]
                    return {"bool": {"must": terms}}
                else:
                    return {"wildcard": {es_field: f"*{field_value}*"}}
            else:
                if isinstance(field_value, list):
                    terms = [{"wildcard": {es_field: f"*{val}*"}} for val in field_value]
                    return {"bool": {"should": terms}}
                else:
                    return {"wildcard": {es_field: f"*{field_value}*"}}
        else:
            if isinstance(field_value, list):
                return {"terms": {es_field: field_value}}
            else:
                return {"term": {es_field: field_value}}

    def process_detection_item(self, item_name, detection_item):
        query_parts = []
        if isinstance(detection_item, list):
            for nested_item in detection_item:
                if isinstance(nested_item, dict):
                    for field_name, field_value in nested_item.items():
                        query_parts.append(self.convert_field_to_es_filter(field_name, field_value))
        else:
            for field_name, field_value in detection_item.items():
                query_parts.append(self.convert_field_to_es_filter(field_name, field_value))

        if len(query_parts) == 1:
            return query_parts[0]

        operator = "should" if item_name.startswith("selection") else "must"
        return {"bool": {operator: query_parts}}

    def build_es_filter(self):
        detection = self.rule_content.get('detection', {})
        if not detection:
            print("[!] No detection section found in rule")
            return False
        condition = detection.get('condition', '').strip()

        detection_items = {}
        for key, value in detection.items():
            if key != 'condition':
                detection_items[key] = self.process_detection_item(key, value)

        filter_query = {}
        if condition:
            if condition.startswith('all of '):
                prefix = condition[len('all of '):].strip()
                if prefix.endswith('*'):
                    prefix = prefix[:-1]
                matching_keys = [k for k in detection_items if k.startswith(prefix)]
                if matching_keys:
                    must = [detection_items[k] for k in matching_keys]
                    filter_query = {"bool": {"must": must}}
            elif condition.startswith('1 of '):
                prefix = condition[len('1 of '):].strip()
                if prefix.endswith('*'):
                    prefix = prefix[:-1]
                matching_keys = [k for k in detection_items if k.startswith(prefix)]
                if matching_keys:
                    should = [detection_items[k] for k in matching_keys]
                    filter_query = {"bool": {"should": should, "minimum_should_match": 1}}
            elif ' and not ' in condition:
                parts = condition.split(' and not ')
                positive_part = parts[0].strip()
                negative_parts = [p.strip() for p in parts[1:]]
                if positive_part.endswith(')'):
                    try:
                        inside_parens = positive_part[1:-1].strip()
                        if ' or ' in inside_parens:
                            or_parts = inside_parens.split(' or ')
                            should_clauses = [detection_items.get(p.strip(), {}) for p in or_parts if p.strip() in detection_items]
                            positive_query = {"bool": {"should": should_clauses, "minimum_should_match": 1}}
                        else:
                            positive_query = detection_items.get(positive_part, {})
                    except:
                        positive_query = detection_items.get(positive_part, {})
                else:
                    positive_query = detection_items.get(positive_part, {})
                must_not = [detection_items.get(p, {}) for p in negative_parts if p in detection_items]
                filter_query = {"bool": {"must": [positive_query], "must_not": must_not}}
            elif ' and ' in condition:
                parts = condition.split(' and ')
                must = [detection_items.get(p.strip(), {}) for p in parts if p.strip() in detection_items]
                filter_query = {"bool": {"must": must}}
            elif ' or ' in condition:
                parts = condition.split(' or ')
                should = [detection_items.get(p.strip(), {}) for p in parts if p.strip() in detection_items]
                filter_query = {"bool": {"should": should, "minimum_should_match": 1}}
            else:
                filter_query = detection_items.get(condition.strip(), {})

        # Fallback: if filter_query is empty, combine all detection items dynamically
        if not filter_query or filter_query == {}:
            all_filters = list(detection_items.values())
            if all_filters:
                filter_query = {"bool": {"must": all_filters}}
            else:
                print("[!] No valid detection items found for rule")
                return False

        self.elastalert_rule['filter'] = [filter_query]
        return True

    def create_elastalert_rule(self):
        self.elastalert_rule['name'] = self.rule_content.get('title', 'Unnamed Rule')
        self.elastalert_rule['type'] = 'any'
        self.elastalert_rule['index'] = 'logs-*'
        self.elastalert_rule['alert'] = ['debug']
        self.elastalert_rule['description'] = self.rule_content.get('description', '')
        self.elastalert_rule['priority'] = LEVEL_TO_PRIORITY.get(self.rule_content.get('level', 'medium'), 3)

        tags = self.rule_content.get('tags', [])
        if tags:
            self.elastalert_rule['tags'] = tags

        false_positives = self.rule_content.get('falsepositives', [])
        if false_positives:
            self.elastalert_rule['realert'] = {"minutes": 10}

        self.elastalert_rule['index'] = 'logs-*'

        logsource = self.rule_content.get('logsource', {})
        product = logsource.get('product', '')
        category = logsource.get('category', '')

        author = self.rule_content.get('author', '')
        if author:
            self.elastalert_rule['owner'] = author

        self.elastalert_rule['timestamp_field'] = '@timestamp'
        self.elastalert_rule['alert_text_args'] = ['@timestamp', 'event.id']
        self.elastalert_rule['alert_text_type'] = 'alert_text_only'

        return True

    def convert(self):
        if not self.load_rule():
            return False
        if not self.build_es_filter():
            return False
        if not self.create_elastalert_rule():
            return False
        if self.output_file:
            try:
                os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    yaml.dump(self.elastalert_rule, f, default_flow_style=False, sort_keys=False)
                self.log(f"Rule successfully converted and saved to {self.output_file}")
            except Exception as e:
                print(f"[!] Error saving output file: {e}")
                return False
        else:
            print(yaml.dump(self.elastalert_rule, default_flow_style=False, sort_keys=False))
        return True

def convert_directory(input_dir, output_dir, verbose=False):
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    # Create output directory if it doesn't exist
    output_path.mkdir(exist_ok=True, parents=True)

    # Find the 'rules' directory in the input path to preserve structure
    rules_index = -1
    path_parts = input_path.parts
    for i, part in enumerate(path_parts):
        if part == 'rules':
            rules_index = i
            break

    # Process all .yml files recursively
    success_count = 0
    fail_count = 0

    for file_path in input_path.glob('**/*.yml'):
        # Calculate relative path starting from 'rules' directory if found
        if rules_index >= 0 and len(path_parts) > rules_index:
            # Get the path starting from the 'rules' directory
            relative_parts = path_parts[rules_index:]
            # Add any subdirectories after the rules directory
            rel_path = file_path.relative_to(input_path)
            preserve_path = Path(*relative_parts) / rel_path
            output_file = output_path / preserve_path.with_suffix('.yaml')
        else:
            # Fallback if 'rules' not found in path
            relative_path = file_path.relative_to(input_path)
            output_file = output_path / relative_path.with_suffix('.yaml')

        output_file.parent.mkdir(exist_ok=True, parents=True)
        converter = SigmaToElastAlert(file_path, output_file, verbose)
        if converter.convert():
            success_count += 1
        else:
            fail_count += 1

    print(f"Conversion complete: {success_count} rules converted successfully, {fail_count} failures")

def get_user_input():
    """Get input directory from user and validate it"""
    while True:
        input_dir = input("Enter the path to Sigma rules directory: ").strip()
        if not input_dir:
            print("Path cannot be empty. Please try again.")
            continue

        path = Path(input_dir)
        if not path.exists():
            print(f"Path '{input_dir}' does not exist. Please try again.")
            continue

        if not path.is_dir():
            print(f"Path '{input_dir}' is not a directory. Please try again.")
            continue

        return input_dir

def main():
    parser = argparse.ArgumentParser(description='Convert Sigma rules to ElastAlert 2 format')
    parser.add_argument('-f', '--file', help='Input Sigma rule file')
    parser.add_argument('-d', '--directory', help='Input directory containing Sigma rules')
    parser.add_argument('-o', '--output', help='Output file or directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-i', '--interactive', action='store_true', help='Use interactive mode for input')

    args = parser.parse_args()

    # Set default output directory in user's home directory
    output_dir = os.path.expanduser('~/elastalert_rules')
    print(f"Output directory: {output_dir}")

    # Ensure output directory exists
    Path(output_dir).mkdir(exist_ok=True, parents=True)

    if args.interactive:
        # Interactive mode - get directory from user
        input_dir = get_user_input()
        print(f"Using input directory: {input_dir}")
        print(f"Output directory will be: {output_dir}")
        convert_directory(input_dir, output_dir, verbose=True)
    elif args.file:
        # Single file mode
        output_file = args.output if args.output else output_dir + '/' + os.path.basename(args.file).replace('.yml', '.yaml')
        converter = SigmaToElastAlert(args.file, output_file, args.verbose)
        if not converter.convert():
            sys.exit(1)
    elif args.directory:
        # Directory mode with command line argument
        convert_directory(args.directory, args.output or output_dir, args.verbose)
    else:
        # No arguments provided, default to interactive mode
        print("No input specified. Switching to interactive mode.")
        input_dir = get_user_input()
        print(f"Using input directory: {input_dir}")
        print(f"Output directory will be: {output_dir}")
        convert_directory(input_dir, output_dir, verbose=True)

if __name__ == "__main__":
    main()
