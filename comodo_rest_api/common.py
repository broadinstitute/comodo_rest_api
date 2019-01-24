from functools import wraps
import logging
import requests

logger = logging.getLogger(__name__)

def version_hack(service, version="v1"):
    """API version hack

    For the most part, the Comodo API uses the same version (v1) for all API calls.
    However, there are a few calls spread throughout the API spec that use "v2"
    currently.  This wrapper is designed to temporarily change the version to
    something other than what the object was initialized with so that the internal
    *self.api_url* will be correct.

    :param version: API version string to use. If None, 'v1'
    """

    def decorator(f):
        @wraps(f)
        def api_version(self, *args, **kwargs):
            if not service:
                raise Exception("version_hack: No service provided")
            if not version:
                raise Exception("version_hack: No version provided")

            api = self._create_api_url(self.base_url, service, "/%s" % version)
            save_url = self.api_url
            self.api_url = api

            try:
                retval = f(self, *args, **kwargs)

                # Reset the api_url back to the original
                self.api_url = save_url

                return retval
            except Exception as e:
                # Reset the api_url back to the original
                self.api_url = save_url
                raise e

        return api_version  # true decorator

    return decorator

class ComodoCA(object):
    """
    Top level class for the Comodo CA. Only very generic 'things' go here.
    """

    formats = {'AOL': 1,
               'Apache/ModSSL': 2,
               'Apache-SSL': 3,
               'C2Net Stronghold': 4,
               'Cisco 3000 Series VPN Concentrator': 33,
               'Citrix': 34,
               'Cobalt Raq': 5,
               'Covalent Server Software': 6,
               'IBM HTTP Server': 7,
               'IBM Internet Connection Server': 8,
               'iPlanet': 9,
               'Java Web Server (Javasoft / Sun)': 10,
               'Lotus Domino': 11,
               'Lotus Domino Go!': 12,
               'Microsoft IIS 1.x to 4.x': 13,
               'Microsoft IIS 5.x and later': 14,
               'Netscape Enterprise Server': 15,
               'Netscape FastTrac': 16,
               'Novell Web Server': 17,
               'Oracle': 18,
               'Quid Pro Quo': 19,
               'R3 SSL Server': 20,
               'Raven SSL': 21,
               'RedHat Linux': 22,
               'SAP Web Application Server': 23,
               'Tomcat': 24,
               'Website Professional': 25,
               'WebStar 4.x and later': 26,
               'WebTen (from Tenon)': 27,
               'Zeus Web Server': 28,
               'Ensim': 29,
               'Plesk': 30,
               'WHM/cPanel': 31,
               'H-Sphere': 32,
               'OTHER': -1,
               }

    format_type = [
        'x509',     # X509, Base64 encoded
        'x509CO',   # X509 Certificate only, Base64 encoded
        'x509IO',   # X509 Intermediates/root only, Base64 encoded
        'base64',   # PKCS#7 Base64 encoded
        'bin',      # PKCS#7 Bin encoded
        'x509IOR',  # X509 Intermediates/root only Reverse, Base64 encoded
    ]


class ComodoService(ComodoCA):
    """
    Class that encapsulates methods to use against Comodo APIs
    """
    def __init__(self, **kwargs):
        """
        :param string base_url: The full URL for the API server
        :param string api_url: The full URL to the versioned endpoint on the API server
        :param string customer_login_uri: The URI for the customer login (if your login to the Comodo GUI is at
                https://hard.cert-manager.com/customer/foo/, your login URI is 'foo').
        :param string login: The login user
        :param string org_id: The organization ID
        :param string password: The API user's password
        :param bool client_cert_auth: Whether to use client certificate authentication
        :param string client_public_certificate: The path to the public key if using client cert auth
        :param string client_private_key: The path to the private key if using client cert auth
        """
        # Using get for consistency and to allow defaults to be easily set
        self.base_url = kwargs.get('base_url')
        self.api_url = kwargs.get('api_url')
        self.customer_login_uri = kwargs.get('customer_login_uri')
        self.login = kwargs.get('login')
        self.org_id = kwargs.get('org_id')
        self.password = kwargs.get('password')
        self.client_cert_auth = kwargs.get('client_cert_auth')
        self.session = requests.Session()
        # Because Comodo is crap at designing APIs (in my opinion) we have to get the wsdl
        # then modify the transport to use client certs after that.
        if self.client_cert_auth:
            self.client_public_certificate = kwargs.get('client_public_certificate')
            self.client_private_key = kwargs.get('client_private_key')
            self.session.cert = (self.client_public_certificate, self.client_private_key)
        self.headers = {
            'login': self.login,
            'password': self.password,
            'customerUri': self.customer_login_uri
        }
        self.session.headers.update(self.headers)

    @staticmethod
    def _create_api_url(base_url, service, version):
        """
        Create a URL from the API URL that the instance was initialized with.

        :param str base_url: The base URL you have i.e. for https://hard.cert-manager.com/api/ssl/v1/ the base URL would be https://hard.cert-manager.com/api
        :param str service: The API service to use i.e. for https://hard.cert-manager.com/api/ssl/v1/ the service would be /ssl
        :param str version: The API version to use i.e. for https://hard.cert-manager.com/api/ssl/v1/ the version would be /v1
        :return: The full URL
        :rtype: str
        """
        url = base_url + service + version
        logger.debug('URL created: %s' % url)

        return url

    def _create_url(self, suffix):
        """
        Create a URL from the API URL that the instance was initialized with.

        :param str suffix: The suffix of the URL you wish to create i.e. for https://example.com/foo the suffix would be /foo
        :return: The full URL
        :rtype: str
        """
        url = self.api_url + suffix
        logger.debug('URL created: %s' % url)

        return url

    def _get(self, url):
        """
        GET a given URL

        :param str url: A URL
        :return: The requests session object

        """
        logger.debug('Performing a GET on url: %s' % url)
        result = self.session.get(url)
        logger.debug('Result code: %s' % result.status_code)
        logger.debug('Result headers: %s' % result.headers)
        logger.debug('Text result: %s' % result.text)

        return result

    def _post(self, url=None, data={}):
        """
        Submit a POST request to the Comodo API

        :param string cert_type_name: The full cert type name (Example: 'PlatinumSSL Certificate') the supported
                                      certificate types for your account can be obtained with the
                                      get_cert_types() method.
        :param string csr: The Certificate Signing Request (CSR)
        :param int term: The length, in days, for the certificate to be issued
        :param string subject_alt_names: Subject Alternative Names separated by a ",".
        :return: The certificate_id and the normal status messages for errors.
        :rtype: dict
        """

        logger.debug('Performing a POST on url: %s' % url)
        result = self.session.post(url, json=data)

        logger.debug('Result code: %s' % result.status_code)
        logger.debug('Result headers: %s' % result.headers)
        logger.debug('Text result: %s' % result.text)

        return result
