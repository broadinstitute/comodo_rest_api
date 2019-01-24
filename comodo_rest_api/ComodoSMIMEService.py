import logging
try:
    from urllib import quote
except Exception as e:
    from urllib.parse import quote

import jsend

from comodo_rest_api.common import ComodoService
from comodo_rest_api.common import version_hack

logger = logging.getLogger(__name__)


class ComodoSMIMEService(ComodoService):
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

        api = self._create_api_url(base_url, "/smime", "/%s" % self._api_version)
        kwargs["base_url"] = base_url
        kwargs["api_url"] = api

        super(ComodoSMIMEService, self).__init__(**kwargs)

    def get_cert_types(self):
        """
        Collect the certificate types that are available to the customer.

        :return: A list of dictionaries of certificate types
        :rtype: list
        """
        url = self._create_url('/types')
        result = self._get(url)

        if result.status_code == 200:
            return jsend.success({'types': result.json()})
        else:
            return jsend.fail(result.json())

    def get_custom_fields(self):
        """
        List all of custom fields defined for S/MIME certificates.

        :return: A list of dictionaries of custom fields
        :rtype: list
        """
        url = self._create_url('/customFields')
        result = self._get(url)

        if result.status_code == 200:
            return jsend.success({'customFields': result.json()})
        else:
            return jsend.fail(result.json())


    def collect(self, order_number):
        """
        Collect a S/MIME certificate.

        :param int order_number: The certificate order number
        :return: The certificate_id or the certificate (in PKCS#7 format) depending on whether the certificate is ready (check status code)
        :rtype: dict
        """

        url = self._create_url('/collect/{}'.format(order_number))
        result = self._get(url)

        # The certificate is ready for collection
        if result.status_code == 200:
            return jsend.success({'certificate': result.content.decode(result.encoding)})
        # The certificate is not ready for collection yet
        elif result.status_code == 400 and result.json()['code'] == 0:
            return jsend.fail()
        # Some error occurred
        else:
            return jsend.fail(result.json())

    def renew(self, cert_id):
        """
        Renew a S/MIME certificate by ID.

        :param int cert_id: The certificate ID
        :return: The result of the operation, 'Successful' on success
        :rtype: dict
        """

        url = self._create_url('/renewById/{}'.format(cert_id))
        result = self._post(url, data='')

        if result.status_code == 200:
            return jsend.success({'certificate_id': result.json()['sslId']})
        else:
            return jsend.fail(result.json())

    def revoke(self, key, revoke_by='email', reason=''):
        """
        Revoke a S/MIME certificate.

        :param str key: The key to use to find the key to revoke (i.e. email, order number, or serial number).
        :param str revoke_by: The key to revoke by.  Accepted values are 'email', 'order', and 'serial'. Defaults to 'email'.
        :param str reason: Reason for revocation (up to 512 characters), can be blank: '', but must exist.
        :return: The result of the operation, 'Successful' on success
        :rtype: dict
        """
        rev_types = ['email', 'order', 'serial']
        data = {}

        if revoke_by not in rev_types:
            raise Exception('Incorrect revoke_by provided')

        data['reason'] = reason

        if revoke_by == 'email':
            url = self._create_url('/revoke')
            data['email'] = key
        elif revoke_by == 'order':
            url = self._create_url('/revoke/order/{}'.format(key))
        elif revoke_by == 'serial':
            url = self._create_url('/revoke/serial/{}'.format(key))

        result = self._post(url, data=data)

        if result.status_code == 204:
            return jsend.success()
        else:
            return jsend.error(result.json()['description'])

    def submit(
        self, cert_type_name, csr, term, email, first_name='', middle_name='',
        last_name='', custom_fields=[],
    ):
        """
        Submit a S/MIME certificate request to Comodo.

        :param string cert_type_name: The full cert type name (Example: 'PlatinumSSL Certificate') the supported
                                      certificate types for your account can be obtained with the
                                      get_cert_types() method.
        :param string csr: The Certificate Signing Request (CSR)
        :param int term: The length, in days, for the certificate to be issued
        :param string email: Well-formed email address, not be empty, 0 and 256 characters.
        :param string first_name: First name
        :param string middle_name: Middle name.
        :param string last_name: Last name.
            firstName + ' ' + middleName + ' ' + lastName must be in range of 1 to 64 characters.
        :param list custom_fields: Custom fields to be applied to requested certificate.
        :return: The certificate_id and the normal status messages for errors.
        :rtype: dict
        """
        cert_types = self.get_cert_types()

        # If collection of cert types fails we simply pass the error back.
        if cert_types['status'] == 'fail':
            return cert_types

        # Find the certificate type ID
        for cert_type in cert_types['data']['types']:
            if cert_type['name'] == cert_type_name:
                cert_type_id = cert_type['id']

        url = self._create_url('/enroll')
        data = {'orgId': self.org_id, 'csr': csr, 'certType': cert_type_id, 'term': term,
            'firstName': first_name, 'middleName': middle_name, 'lastName': last_name,
            'customFields': custom_fields}
        result = self._post(url, data=data)

        if result.status_code == 200:
            return jsend.success({'order_number': result.json()['orderNumber']})
        # Anything else is an error
        else:
            return jsend.error(result.json()['description'])

    @version_hack(service='/smime', version='v2')
    def find(self, key, find_by='id'):
        """
        Find an S/MIME certificate.

        :param str key: The key to use to find the key to revoke (i.e. email, order number, or serial number).
        :param str find_by: The key to find by.  Accepted values are 'email' and 'id'. Defaults to 'email'.
        :return: The result of the operation, 'Successful' on success
        :rtype: dict
        """
        find_types = ['id', 'email']

        if find_by not in find_types:
            raise Exception('Incorrect find_by provided')

        if find_by == 'id':
            path = '/byPersonId/{}'.format(key)
        elif find_by == 'email':
            path = '/byPersonEmail/{}'.format(quote(key))

        url = self._create_url(path)
        result = self._get(url)

        # The certificate is ready for collection
        if result.status_code == 200:
            return jsend.success({'info': result.content.decode(result.encoding)})
        # Some error occurred
        else:
            return jsend.fail(result.json())
