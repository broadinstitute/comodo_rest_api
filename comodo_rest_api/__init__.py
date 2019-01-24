from pkg_resources import get_distribution, DistributionNotFound
try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    # package is not installed
    pass

from comodo_rest_api.common import *
from comodo_rest_api.ComodoOrganization import ComodoOrganization
from comodo_rest_api.ComodoSMIMEService import ComodoSMIMEService
from comodo_rest_api.ComodoTLSService import ComodoTLSService

__all__ = [
    "ComodoCA", "ComodoService", "ComodoOrganization", "ComodoSMIMEService",
    "ComodoTLSService"
]
