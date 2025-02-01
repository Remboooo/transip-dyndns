import argparse
import logging
import yaml
import sys
import os
import urllib.error
import re
from collections import defaultdict

import transip

ipv4_url = 'https://icanhazip.com'

log = logging.getLogger('transip-dyndns')


class ConfigError(BaseException):
    pass


def get_ipv4():
    import urllib.request
    ipv4 = urllib.request.urlopen(ipv4_url).read().decode('ascii').strip()
    if not re.fullmatch(r'^([0-2]?[0-9]?[0-9][.]){3}[0-2]?[0-9]?[0-9]$', ipv4):
        raise ValueError("'{}' returned invalid IPv4 address '{}'".format(ipv4_url, ipv4))
    return ipv4


def update_a_records(config_domains, avail_domains, expire_time, client):
    domain_records = defaultdict(set)

    # Create inventory of which records to update for each domain
    for fqdn in config_domains:
        parts = fqdn.strip().rsplit('.', 2)
        if len(parts) < 2:
            raise ConfigError("Invalid domain in configuration: '{}'".format(fqdn))
        elif len(parts) == 2:
            record, (domain, tld) = '@', parts
        else:
            record, domain, tld = parts
        domain = "{}.{}".format(domain, tld)
        if not any(avail_domain.name == domain for avail_domain in avail_domains):
            raise ConfigError("Configured domain '{}' does not belong to this account".format(domain))
        log.debug("A record to update: '{}' on domain '{}'".format(record, domain))
        domain_records[domain].add(record)

    if not domain_records:
        log.debug("No A records configured to update")
        return

    ipv4 = get_ipv4()
    log.debug("Found external IPv4 address {}".format(ipv4))

    updated = False

    # Update records
    for domain, records in domain_records.items():
        domain_service = client.domains.get(domain)
        entries = domain_service.dns.list()

        # Update existing entries
        for entry in entries:
            if entry.type != 'A':
                continue
            if entry.name not in records:
                continue
            log.debug("Found relevant A record on {}: {}".format(domain, entry))
            records.remove(entry.name)
            if entry.content == ipv4:
                log.debug("A record for '{}' on domain '{}' is already up to date".format(entry.name, domain))
            else:
                log.info("Updating A record for '{}' on domain '{}' to '{}'".format(entry.name, domain, ipv4))
                entry.content = ipv4
                entry.update()
        
        # Create new entries
        for new_record in records:
            log.info("Creating new A record for '{}' on domain '{}' with content '{}' and expiry {}".format(new_record, domain, ipv4, expire_time))
            domain_service.dns.create({"name": new_record, "expire": expire_time, "type": "A", "content": ipv4})


def run(config, config_path):
    try:
        username, keyfile, a_records, expire_time = config['username'], config['keyfile'], config['A'], config['expire']
        expire_time = int(expire_time)
    except KeyError as e:
        raise ConfigError('Configuration is missing field {}'.format(str(e)))

    # If keyfile is a relative path, make it an absolute path by resolving it from the config file path
    if not os.path.isabs(keyfile):
        keyfile = os.path.abspath(os.path.join(os.path.dirname(config_path), keyfile))

    with open(keyfile, 'r') as f:
        key = f.read()

    client = transip.TransIP(login=username, private_key=key, global_key=True)
    domains = client.domains.list()
    log.debug("Domains managed by TransIP on this account: {}".format(domains))
    update_a_records(a_records, domains, expire_time, client)


def main():
    parser = argparse.ArgumentParser(description='TransIP dynamic DNS updater')
    parser.add_argument('-f', '--file', type=str, default='transip_config.yml', help='Path to configuration file to use')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    args = parser.parse_args()
    
    log_level = logging.DEBUG if args.verbose else logging.WARNING

    logging.basicConfig(stream=sys.stdout, format='%(asctime)s %(levelname)s [%(name)s] %(message)s')
    log.setLevel(log_level)
    
    try:
        with open(args.file, 'r') as f:
            try:
                config = yaml.safe_load(f)
                run(config, os.path.abspath(args.file))
            except yaml.YAMLError as e:
                log.error("Error in config file: {}".format(e))
                sys.exit(-1)
    except OSError as e:
        log.error("Could not open config file: {}".format(e), e)
        sys.exit(-1)
    except ConfigError as e:
        log.error(str(e))
        sys.exit(-1)


if __name__ == '__main__':
    main()

