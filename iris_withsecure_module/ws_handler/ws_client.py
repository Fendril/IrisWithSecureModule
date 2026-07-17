import re
import requests
import logging as log

from urllib3.util import Retry

class WSClientError(Exception):
    """Basic Error Class"""
    pass

class EmptySearchtermError(WSClientError):
    """Exception raised, when no search terms are given."""
    pass

class CertificateNotFoundError(WSClientError):
    pass

class WSClient:
    """The WSClient class just hides the "complexity" of the queries.
    All params can be lists to query more than one WithSecure Instance.
    
    :param withsecure_api_secret: API key
    :type withsecure_api_secret: str  
    :param withsecure_api_clientid: API key username
    :type withsecure_api_clientid: str
    :param ws_token: Token stored after authenticate for further queries
    :type ws_token: str
    """
    
    def __init__(self, api_secret: str, api_clientid: str, logger: log):
        self.log = logger
        if re.match(r"^[a-zA-Z0-9]{32}$", api_secret.strip()):
            self._withsecure_api_secret = api_secret
        if re.match(r"^[a-zA-Z0-9]+_[a-zA-Z0-9]{24}$", api_clientid.strip()):
            self._withsecure_api_clientid = api_clientid
        self._ws_token = None

    def authenticate(self):
        """ Authenticate to WithSecure serveurs using API key and keyname
        to obtain the token for further queries

        Keep the token inside the class itself
        """
        datas = {
            'grant_type': 'client_credentials',
            'scope': 'connect.api.read'
        }
        retry_protector = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504]
        )
        adaptator = requests.adapters.HTTPAdapter(max_retries=retry_protector)
        session = requests.Session()
        session.mount("https://", adaptator)
        if self._withsecure_api_secret and self._withsecure_api_clientid:
            session.auth = (self._withsecure_api_clientid, self._withsecure_api_secret)
        else:
            raise TypeError

        try:
            auth = session.post(
                url='https://api.connect.withsecure.com/as/token.oauth2',
                data=datas,
            )
            auth.raise_for_status()
            response = auth.json()
        except requests.exceptions.HTTPError as err:
            self.log.error(f"HTTP Error occured : {err}")
        except requests.exceptions.ConnectionError as err:
            self.log.error(f"Error connexion failed after 3 DNS requests : {err}")
        except Exception as err:
            self.log.error(f"Error occured : {err}")
        if "access_token" in response:
            self._ws_token = response["access_token"]
        else:
            exit()
        
    def get_detections(self, bcd_id: str):
        """ Gather informations from given BCD ID

        :param bcd_id: Is the ID of BCD Element to gather
        :bcd_id: str
        :rtype: json
        """
        WS_API_DETECTIONS_URL = "https://api.connect.withsecure.com/incidents/v1/detections"
        if re.match(r'^[a-zA-Z0-9]{8}(?:-[a-z0-9]{4}){3}-[a-z0-9]{12}$', bcd_id):
            headers = {
                "Authorization": f"Bearer {self._ws_token}",
                "Content-Type": "application/json",
            }
            params = {
                "incidentId": bcd_id
            }
            try:
                req = requests.get(
                    url=WS_API_DETECTIONS_URL,
                    headers=headers,
                    params=params
                )
                req.raise_for_status()
                resp = req.json()
                return resp
            except requests.exceptions.HTTPError as err:
                self.log.error(f"Erreur HTTP survenue : {err}")
            except Exception as err:
                self.log.error(f"Une autre erreur est survenue : {err}")
    
    def get_device(self, device_id: str):
        """
        TODO : Fonction de récupération d'informations d'un Device à partir de l'ID
        Withsecure ex : d67e2605-66b8-4c33-869d-589254062835
        URL API : curl -v -X GET
            -H "Authorization: Bearer zM5pMCdgt6qcH3KrxZiOVOutY7qSdfDwCCIaiTRAM0sHpbDQ3ECbwhZI1OeGrsCXgXuVI7LAvSdTYDLwetab982glOHf"
            -H "Content-Type: application/json"
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"
            https://api.connect.withsecure.com/devices/v1/devices?deviceId=d67e2605-66b8-4c33-869d-589254062835
        """
        WS_API_GET_DEVICE_URL = "https://api.connect.withsecure.com/devices/v1/devices"
        if re.match(r'^[a-z0-9]{8}(?:-[a-z0-9]{4}){3}-[a-z0-9]{12}$', device_id):
            headers = {
                "Authorization": f"Bearer {self._ws_token}",
                "Content-Type": "application/json",
            }
            params = {
                "deviceId": f"{device_id}"
            }
            try:
                req = requests.get(url=WS_API_GET_DEVICE_URL, headers=headers, params=params)
                req.raise_for_status()
                resp = req.json().get("items")[0]
                return resp
            except requests.exceptions.HTTPError as err:
                self.log.error(f"Erreur HTTP survenue : {err}")
            except Exception as err:
                self.log.error(f"Une autre erreur est survenue : {err}")
