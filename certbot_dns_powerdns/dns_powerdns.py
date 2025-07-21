"""DNS Authenticator for PowerDNS."""
from __future__ import annotations

import logging

import zope.interface
from certbot import interfaces
from certbot import errors

from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

from lexicon.providers import powerdns

logger = logging.getLogger(__name__)

class _PowerDNSLexiconClient(dns_common_lexicon.LexiconClient):
	"""
	Encapsulates all communication with the PowerDNS via Lexicon.
	"""

	def __init__(self, api_url: str, api_key: str, ttl: int) -> None:
		super(_PowerDNSLexiconClient, self).__init__()

		config = dns_common_lexicon.build_lexicon_config('powerdns', {
			'ttl': ttl,
		}, {
			'auth_token': api_key,
			'pdns_server': api_url,
		})

		self.provider = powerdns.Provider(config)

	def _handle_http_error(self, e, domain_name: str) -> (errors.PluginError | None):
		if domain_name in str(e) and (
			# 4.0
			str(e).startswith('422 Client Error: Unknown Status for url') or
			# 4.0 and 4.1 compatibility
			str(e).startswith('422 Client Error: Unprocessable Entity for url:') or
			# 4.2
			str(e).startswith('404 Client Error: Not Found for url:') or
			# 4.8.3
			str(e).startswith('404 Client Error: NOT FOUND for url:')
			):
			return  # Expected errors when zone name guess is wrong
		return super(_PowerDNSLexiconClient, self)._handle_http_error(e, domain_name)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
	"""DNS Authenticator for PowerDNS DNS."""

	description = 'Obtain certificates using a DNS TXT record (if you are using PowerDNS for DNS.)'

	ttl: int = 60

	def __init__(self, *args, **kwargs) -> None:
		super(Authenticator, self).__init__(*args, **kwargs)
		self.credentials = None

	@classmethod
	def add_parser_arguments(cls, add) -> None:
		super(Authenticator, cls).add_parser_arguments(
			add, default_propagation_seconds=60)
		add("credentials", help="PowerDNS credentials file.")

	def more_info(self) -> str:  # pylint: disable=missing-docstring,no-self-use
		return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using PowerDNS API'

	def _setup_credentials(self) -> None:
		self._configure_file('credentials', 'Absolute path to PowerDNS credentials file')
		dns_common.validate_file_permissions(self.conf('credentials'))
		self.credentials = self._configure_credentials(
			'credentials',
			'PowerDNS credentials file',
			{
				'api-url': 'PowerDNS-compatible API FQDN',
				'api-key': 'PowerDNS-compatible API key (X-API-Key)'
			}
		)

	def _perform(self, domain: str, validation_name: str, validation: str) -> None:
		self._get_powerdns_client().add_txt_record(
			domain, validation_name, validation)

	def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
		self._get_powerdns_client().del_txt_record(
			domain, validation_name, validation)

	def _get_powerdns_client(self) -> _PowerDNSLexiconClient:
		return _PowerDNSLexiconClient(
			self.credentials.conf('api-url'),
			self.credentials.conf('api-key'),
			self.ttl
		)
