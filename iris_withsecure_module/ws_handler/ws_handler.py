import iris_interface.IrisInterfaceStatus as InterfaceStatus
import logging as log
import traceback
import requests
import re
import urllib3

from iris_interface import IrisInterfaceStatus
from iris_withsecure_module.ws_handler.ws_client import WSClient, WSClientError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WSHandler:
    def __init__(self, logger: log, case_id: int, mod_config = None):
        self.mod_config = mod_config
        self.withsecure_api_secret = self.mod_config.get('withsecure_api_secret')
        self.withsecure_api_clientid = self.mod_config.get('withsecure_api_clientid')
        self.withsecure = None
        self.iris_api_key = self.mod_config.get('iris_api_key')
        self.iris_fqdn = self.mod_config.get('iris_fqdn')
        self.log = logger
        self.iris_case_id = case_id

    def load_withsecure_instance(self):
        """
        Initiates WS instance communication
        :returns WSClient object
        """
        try:
            self.withsecure = WSClient(
                api_secret = self.withsecure_api_secret,
                api_clientid = self.withsecure_api_clientid,
                logger = self.log
            )
            self.withsecure.authenticate()
        except WSClientError as e:
            self.log.error(f'WSClient Error initiating WithSecure instance {e}')
            return InterfaceStatus.I2Error(traceback.format_exc())
        except TypeError as te:
            self.log.error(f'Type Error initiating WithSecure instance {te}')
            return InterfaceStatus.I2Error(traceback.format_exc())
        
        return InterfaceStatus.I2Success()

    def get_ws_instance(self):
        """
        Returns WS Instance
        """
        try:
            if self.withsecure is None:
                self.withsecure = self.load_withsecure_instance()
                self.withsecure.authenticate()
        except Exception:
            return InterfaceStatus.I2Error(traceback.format_exc())

        return self.withsecure
    
    def get_detections(self, bcd_id: str):
        """
        Call WS API to gather all information over an Incident ID
        :param bcd_id: ID to Gather, need to be passed to an instanciated
        and authenticated WSClient.

        :rtype: InterfaceStatus.I2
        """
        try:
            ws_json = self.withsecure.get_detections(bcd_id)
            self._handle_ws_response(ws_json)
        except Exception:
            return InterfaceStatus.I2Error(traceback.format_exc())
        
        return InterfaceStatus.I2Success()
    
    def _handle_ws_response(self, json):
        """
        Handles the JSON formated data, extract informations and
        add IoCs & assets directly to the case.
        :param json: Contains the JSON formated information from WS API
        response.
        """
        binary_iocs_set = set()
        ips_iocs_set = set()
        assets_set = set()
        account_iocs_set = set()
        try:
            for item in json["items"]:
                if item["severity"] in ["high", "critical"] or item["riskLevel"] in ["high", "critical"]:
                    if "exeName" in item and "exeHash" in item:
                        tmp_dict = {
                            "exeName": item["exeName"],
                            "exeHash": item["exeHash"],
                            "exePath": item["exePath"]
                        }
                        binary_iocs_set.add(tuple(tmp_dict.items()))
                    if "username" in item:
                        if item.get('username'):
                            account_iocs_set.add(item["username"])
                            assets_set.add(item['username'])
                    if "activityContext" in item:
                        for activity_context in item["activityContext"]:
                            tmp_dict = dict()
                            if "destinationIp" in activity_context:
                                tmp_dict.update({"dstip": activity_context["destinationIp"]})
                            if "destinationPort" in activity_context:
                                tmp_dict.update({"dstport": activity_context["destinationPort"]})
                            if "sourceIp" in activity_context:
                                tmp_dict.update({"srcip": activity_context["sourceIp"]})
                            if "sourcePort" in activity_context:
                                tmp_dict.update({"srcPort": activity_context["sourcePort"]})
                            if tmp_dict:
                                ips_iocs_set.add(tuple(tmp_dict.items()))
                    if "description" in item:
                        tmp_dict.update({"desc": item.get('description')})
                
                if "deviceId" in item:
                    assets_set.add(item["deviceId"])
            
        except Exception as err:
            self.log.error(f"{err}")
        
        if assets_set:
            self._handle_assets_set(assets_set)
        if binary_iocs_set:
            self._handle_iocs_set(binary_iocs_set)
        if ips_iocs_set:
            self._handle_iocs_set(ips_iocs_set)
        if account_iocs_set:
            self._handle_iocs_set(account_iocs_set)


    def _handle_iocs_set(self, iocs_set: set):
        """
        Handles an IoCs set to insert new Iocs into the case.
        """
        IRIS_API_IOC_CREATE_URL = f"https://{self.iris_fqdn}/case/ioc/add"
        headers = {
            "Authorization": f"Bearer {self.iris_api_key}",
            "Content-Type": "application/json"
        }

        for iocs in iocs_set:
            iocs = self._tuple_to_dict(iocs)
            params = {
                "cid": f"{self.iris_case_id}"
            }
            payload = {
                "ioc_type_id": "",
                "ioc_tlp_id": 2,
                "ioc_value": "",
                "ioc_description": "",
                "ioc_tags": "edr,radar",
            }
            try:
                if isinstance(iocs, dict):
                    if "dstip" in iocs or "srcip" in iocs:
                        if "dstport" in iocs:
                            payload.update({
                                "ioc_type_id": "78",
                                "ioc_value": f"{iocs.get('dstip')}|{iocs.get('dstport')}",
                                "ioc_description": f"{iocs.get('desc') if iocs.get('desc') else ''}"
                            })
                        if "srcport" in iocs:
                            payload.update({
                                "ioc_type_id": "80",
                                "ioc_value": f"{iocs.get('srcip')}|{iocs.get('srcport')}",
                                "ioc_description": f"{iocs.get('desc') if iocs.get('desc') else ''}"
                            })
                    elif "exeName" in iocs:
                        if "exeHash" in iocs:
                            payload.update({
                                "ioc_type_id": "44",
                                "ioc_value": f"{iocs.get('exeName')}|{iocs.get('exeHash')}",
                                "ioc_description": f"{iocs.get('desc') if iocs.get('desc') else ''}"
                            })
                        else:
                            payload.update({
                                "ioc_type_id": "37",
                                "ioc_value": f"{iocs.get('exeName')}",
                                "ioc_description": f"{iocs.get('desc') if iocs.get('desc') else ''}"
                            })
                    elif "exePath" in iocs:
                        payload.update({
                            "ioc_type_id": "97",
                            "ioc_value": f"{iocs.get('exePath')}",
                            "ioc_description": f"{iocs.get('desc') if iocs.get('desc') else ''}"
                        })

                else:
                    payload.update({
                        "ioc_type_id": "3",
                        "ioc_value": f"{iocs}",
                    })
                
                req = requests.post(
                    url=IRIS_API_IOC_CREATE_URL,
                    headers=headers,
                    json=payload,
                    params=params,
                    verify=False
                )
                req.raise_for_status()
                self.log.info(f"Sent POST Request to add IoC {payload.get('ioc_value')} with status code : {req.status_code}")
            except requests.exceptions.HTTPError as err:
                if err.response.status_code == 400:
                    self.log.error(f"Error 400 catched : {err.response.content}")
                    self.log.error(f"IoCs were : {iocs_set}")
                else:
                    self.log.error(f"HTTP Error occured : {err}")
                return IrisInterfaceStatus.I2Error(traceback.format_exc())
            except Exception as err:
                self.log.error(f"Error occured : {err}")
                return IrisInterfaceStatus.I2Error(traceback.format_exc())

    def _handle_assets_set(self, assets_set: set):
        """
        Handles an Assets set to insert into the case.
        """
        IRIS_API_ASSET_CREATE_URL = f"https://{self.iris_fqdn}/case/assets/add"
        headers = {
            "Authorization": f"Bearer {self.iris_api_key}",
            "Content-Type": "application/json"
        }
        for asset in assets_set:
            try:
                if re.match(r'^[a-zA-Z0-9]{8}(?:-[a-z0-9]{4}){3}-[a-z0-9]{12}$', asset):
                    ws_json = self.withsecure.get_device(asset)
                    if ws_json:
                        if ws_json.get("type") == "computer":
                            os_name = ws_json.get("os").get("name")
                            if re.match(r'^Windows', os_name):
                                if re.match(r'(?i)Server', os_name):
                                    asset_type_id = "10"
                                else:
                                    asset_type_id = "9"
                            elif re.match(r'(?i)^(?:Debian|Ubuntu|Alma|Amazon|Oracle|RHEL|Red\s?Hat|Rocky|SUSE)', os_name):
                                asset_type_id = "3"
                            elif re.match(r'(?i)^macOS'):
                                asset_type_id="6"
                            else:
                                self.log.error(f"Error with unrecognized Asset {ws_json.get('name')} Operating System : {os_name}")
                                continue
                else:
                    asset_type_id = "1"
                
                params = {
                    "cid": f"{self.iris_case_id}"
                }
                if asset_type_id == "1":
                    cap_username = re.match(r'^(?:\S+\\)?(\S+)$', asset)
                    payload = {
                        "asset_type_id": f"{asset_type_id}",
                        "asset_compromise_status_id": "0",
                        "analysis_status_id": "2",
                        "asset_name": f"{cap_username.group(1)}",
                        "asset_tags": "edr, withsecure",
                        "asset_description": "Asset created by IrisWithSecureModule.",
                    }
                    cap_domain = re.match('^(\S+)\\\S+$', asset)
                    if cap_domain:
                        payload.update({
                            "asset_domain": f"{cap_domain.group(1)}"
                        })
                else:
                    payload = {
                        "asset_type_id": f"{asset_type_id}",
                        "asset_info": f"Modèle : {ws_json.get('computerModel')}",
                        "asset_compromise_status_id": "0",
                        "analysis_status_id": "2",
                        "asset_name": f"{ws_json.get('name')}",
                        "asset_tags": "edr, withsecure",
                        "asset_description": "Asset created by IrisWithSecureModule.",
                    }
                    if "activeDirectoryGroup" in ws_json:
                        payload.update({"asset_domain": f"{ws_json.get('activeDirectoryGroup') if ws_json.get('activeDirectoryGroup') else ''}"})
                    cap = re.search(r'^((?:\d{1,3}\.){3}\d{1,3})', ws_json.get('ipAddresses'))
                    if cap:
                        payload.update({"asset_ip": f'{cap.group(1)}'})
                req = requests.post(
                    url=IRIS_API_ASSET_CREATE_URL,
                    headers=headers,
                    json=payload,
                    params=params,
                    verify=False
                )
                req.raise_for_status()
                self.log.info(f"Sent POST Request to add Asset {payload.get('asset_name')} with status code : {req.status_code}")

            except requests.exceptions.HTTPError as err:
                if err.response.status_code == 400:
                    err_json = err.response.json()
                    if err_json.get("data")[0] == "Asset name already exists in this case":
                        self.log.info(f"Asset {payload.get('asset_name')} already exists, skipping.")
                        continue
                    else:
                        self.log.error(f"Error HTTP 400 : {err_json}")
                        self.log.error(f"Asset was : {ws_json}")
                        return IrisInterfaceStatus.I2Error(traceback.format_exc())
                else:
                    self.log.error(f"HTTP Error occured : {err}")
                    return IrisInterfaceStatus.I2Error(traceback.format_exc())

            except Exception as err:
                self.log.error(f"Une autre erreur est survenue : {err}")
                return IrisInterfaceStatus.I2Error(traceback.format_exc())

    def _tuple_to_dict(self, structure):
        """
        Convertit récursivement un tuple de paires (clé, valeur) en dictionnaire,
        en gérant l'imbrication des sous-tuples de paires.
        """
        if isinstance(structure, tuple) and all(isinstance(item, tuple) and len(item) == 2 for item in structure):
            return {cle: self._tuple_to_dict(valeur) for cle, valeur in structure}
        
        elif isinstance(structure, (tuple, list)):
            return type(structure)(self._tuple_to_dict(item) for item in structure)
            
        return structure