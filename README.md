[![Build Status](https://travis-ci.com/pan-net-security/certbot-dns-powerdns.svg?branch=master)](https://travis-ci.com/pan-net-security/certbot-dns-powerdns)
[![Coverage Status](https://coveralls.io/repos/github/pan-net-security/certbot-dns-powerdns/badge.svg?branch=master)](https://coveralls.io/github/pan-net-security/certbot-dns-powerdns?branch=master)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=6cfb0c4728624ebff38afc0b1ef91700795ea9ef&metric=alert_status)](https://sonarcloud.io/dashboard?id=6cfb0c4728624ebff38afc0b1ef91700795ea9ef)
![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/github/pan-net-security/certbot-dns-powerdns.svg)
![PyPI - Status](https://img.shields.io/pypi/status/certbot-dns-powerdns.svg)

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/certbot-dns-powerdns.svg)


certbot-dns-powerdns
============

PowerDNS DNS Authenticator plugin for [Certbot](https://certbot.eff.org/).

This plugin is built from the ground up and follows the development style and life-cycle
of other `certbot-dns-*` plugins found in the
[Official Certbot Repository](https://github.com/certbot/certbot).

Installation
------------

```bash
pip install --upgrade certbot
pip install certbot-dns-powerdns
```

Verify:

```bash
$ certbot plugins
...
* dns-powerdns
Description: Obtain certificates using a DNS TXT record (if you are using
PowerDNS for DNS.)
Interfaces: Authenticator, Plugin
Entry point: EntryPoint(name='dns-powerdns',
value='certbot_dns_powerdns.dns_powerdns:Authenticator',
group='certbot.plugins')
...
```

Configuration
-------------

The credentials file e.g. `~/pdns-credentials.ini` should look like this:

```ini
dns_powerdns_api_url = https://api.mypowerdns.example.org
dns_powerdns_api_key = AbCbASsd!@34
# Optionally, if you have two DNS servers that are not linked
dns_powerdns_api_url_secondary = https://api.mypowerdns-2.example.org
dns_powerdns_api_key_secondary = AbCbASsd!@34
# Optionally, if you are verifying another domain via a CNAME
# This example would be requesting *.sub.example.com
# But actually verifying it against a record on *.sub.shadow.com
# This requires you to set up the CNAME on example.com domain pointing to shadow.com
# This is useful if you do not have feasible API access to example.com
dns_powerdns_shadow_domain = shadow.com
dns_powerdns_shadow_domain_replaces = example.com

```

Usage
-----


```bash
certbot ... \
        --authenticator dns-powerdns  \
        --dns-powerdns-credentials ~/pdns-credentials.ini \
        certonly
```

FAQ
-----

Development
-----------

Create a virtualenv, install the plugin (`editable` mode),
spawn the environment and run the test:

```bash
virtualenv -p python3 .venv
. .venv/bin/activate
pip install -e .
docker compose up -d
./test/run_certonly.sh test/pdns-credentials.ini
```

License
--------

Copyright (c) 2019 [DT Pan-Net s.r.o](https://github.com/pan-net-security)
