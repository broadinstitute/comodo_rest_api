import logging
try:
    from urllib import quote
except Exception as e:
    from urllib.parse import quote

import jsend

from comodo_rest_api.common import ComodoService

logger = logging.getLogger(__name__)


class ComodoOrganization(ComodoService):
    """
    Class that encapsulates methods to use against Comodo S/MIME certificates
    """
    def __init__(self, **kwargs):
        """
        :param string api_url: The full URL for the API server
        :param string api_version: The API version to use
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
        base_url = kwargs.pop("api_url")
        self._api_version = kwargs.pop("api_version", "v1")

        api = self._create_api_url(
            base_url, "/organization", "/%s" % self._api_version
        )
        kwargs["base_url"] = base_url
        kwargs["api_url"] = api

        super(ComodoOrganization, self).__init__(**kwargs)

    def get(self):
        """
        Return a list of organizations from Comodo

        :return: A list of dictionaries representing the organizations
        :rtype: list
        """

        result = self._get(self.api_url)

        # The certificate is ready for collection
        if result.status_code == 200:
            return jsend.success({'organizations': result.json()})
        # Some error occurred
        else:
            return jsend.fail(result.json())
