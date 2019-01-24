from betamax import Betamax
from betamax_serializers.pretty_json import PrettyJSONSerializer
import comodo_rest_api
import os
import pytest


customer_login_uri = os.environ.get('CUSTOMER_LOGIN_URI', 'comodo')
login = os.environ.get('LOGIN', 'comodo')
org_id = os.environ.get('ORG_ID', '1234')
password = os.environ.get('PASSWORD', 'fubar')
# Whether to use Client Certificate Authentication against the Comodo API
client_cert_auth = os.environ.get('CLIENT_CERT_AUTH') in ['True', 'true', '1']
client_public_certificate = os.environ.get('CLIENT_PUBLIC_CERTIFICATE', '/tmp/client.crt')
client_private_key = os.environ.get('CLIENT_PRIVATE_KEY', '/tmp/client.key')
csr = os.environ.get('CSR', b'----BEGIN CERTIFICATE REQUEST-----\n<CSR_DATA>\n-----END CERTIFICATE REQUEST-----')

# Makes the output more readable
Betamax.register_serializer(PrettyJSONSerializer)

config = Betamax.configure()
config.cassette_library_dir = 'tests/integration/cassettes'
config.default_cassette_options['placeholders'] = [
    {
        'placeholder': '<PASSWORD>',
        'replace': password
    },
    {
        'placeholder': '<LOGIN>',
        'replace': login
    },
    {
        'placeholder': '<ORG_ID>',
        'replace': org_id
    },
    {
        'placeholder': '<CUSTOMER_LOGIN_URI>',
        'replace': customer_login_uri
    },
    {
        'placeholder': '<CSR_DATA>',
        'replace': csr
    }
]


# A 'good' working client
@pytest.fixture(scope='class')
def api_client():
    yield comodo_rest_api.ComodoTLSService(api_url='https://hard.cert-manager.com/api',
                                      customer_login_uri=customer_login_uri, login=login, org_id=org_id,
                                      client_cert_auth=True,
                                      client_public_certificate=client_public_certificate,
                                      client_private_key=client_private_key, password=password)


# A 'bad' or bogus client to generate errors
@pytest.fixture(scope='class')
def bad_api_client():
    yield comodo_rest_api.ComodoTLSService(api_url='https://hard.cert-manager.com/api',
                                      customer_login_uri='BadURI', login='BadLogin', org_id=1234,
                                      client_cert_auth=False, password='BadPassword')


class TestComodoAPI(object):
    def test_get_cert_types(self, api_client):
        recorder = Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_get_cert_types', serialize_with='prettyjson'):
            result = api_client.get_cert_types()

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']
        assert 'data' in result
        assert 'types' in result['data']
        assert isinstance(result['data']['types'], list)

    def test_get_cert_types_failure(self, bad_api_client):
        recorder = Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_get_cert_types_failure', serialize_with='prettyjson'):
            result = bad_api_client.get_cert_types()

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'fail' in result['status']

    def test_collect(self, api_client):
        recorder = Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_collect', serialize_with='prettyjson'):
            result = api_client.collect(cert_id=655043, format_type='X509CO')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']
        assert 'data' in result
        assert 'certificate' in result['data']
        assert 'certificate_id' in result['data']
        assert 'certificate_status' in result['data']

    def test_collect_failure(self, bad_api_client):
        recorder = Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_collect_failure', serialize_with='prettyjson'):
            result = bad_api_client.collect(cert_id=123456, format_type='X509 PEM Bundle')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'fail' in result['status']

    def test_renew(self, api_client):
        recorder = Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_renew', serialize_with='prettyjson'):
            result = api_client.renew(cert_id=655944)

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']
        assert 'data' in result
        assert 'certificate_id' in result['data']

    def test_renew_failure(self, bad_api_client):
        recorder = Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_renew_failure', serialize_with='prettyjson'):
            result = bad_api_client.renew(cert_id=655944)

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'fail' in result['status']

    def test_revoke(self, api_client):
        recorder = Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_revoke', serialize_with='prettyjson'):
            result = api_client.revoke(cert_id=655674, reason='Revoked for testing')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']

    def test_revoke_failure(self, bad_api_client):
        recorder = Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_revoke_failure', serialize_with='prettyjson'):
            result = bad_api_client.revoke(cert_id=123456, reason='Revoked for testing')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'error' in result['status']

    def test_submit(self, api_client):
        recorder = Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_submit', serialize_with='prettyjson'):
            result = api_client.submit(cert_type_name='Comodo Unified Communications Certificate',
                                       csr=csr, term=365, subject_alt_names='test2.colorado.edu')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']
        assert 'data' in result
        assert 'certificate_id' in result['data']

    def test_submit_failure(self, bad_api_client):
        recorder = Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_submit_failure', serialize_with='prettyjson'):
            result = bad_api_client.submit(cert_type_name='Comodo Unified Communications Certificate',
                                           csr=csr, term=365, subject_alt_names='test2.colorado.edu')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'fail' in result['status']
