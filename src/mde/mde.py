import json
import logging as log
import urllib.request
import urllib.parse
import logging
from pprint import pprint

import requests

"""
Configure Logging
"""
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class defender:
    def __init__(self, config):
        log.debug("[MSAlerts::__init__]")
        self._cfg = config
        self._api_url = config["api_url"]
        self._tenantId = config["tenant_id"]
        self._appId = config["client_id"]
        self._appSecret = config["client_secret"]
        aadToken = self._startauth()
        self._headers = {"Authorization": "Bearer " + aadToken}

    def _startauth(self):
        url = "https://login.microsoftonline.com/%s/oauth2/token" % self._tenantId

        resourceAppIdUri = self._api_url

        body = {
            "resource": resourceAppIdUri,
            "client_id": self._appId,
            "client_secret": self._appSecret,
            "grant_type": "client_credentials",
        }

        data = urllib.parse.urlencode(body).encode("utf-8")

        response = requests.request("GET", url, data=data)
        if response.status_code == 200:
            aadToken = response.json()["access_token"]
            return aadToken
        else:
            return False

    def _get(self, url, output=[]):
        response = requests.request("GET", url, headers=self._headers)
        if response.status_code == 200:
            response = response.json()
            if "value" not in response:
                return response
            output = output + response["value"]
            if "@odata.nextLink" in response:
                logger.info(f'Next URL: {response["@odata.nextLink"]}')
                output = self._get(response["@odata.nextLink"], output)
            else:
                return output
        else:
            error = response.json()["error"]
            logger.error(error["message"])
        return output

    def _post(self, url, payload):
        response = requests.request("POST", url, headers=self._headers, json=payload)
        if response.status_code == 200:
            response = response.json()
            return response
        else:
            error = response.json()["error"]
            logger.error(error["message"])
            return False

    def get_vulnerabilites(self):
        url = self._api_url + "/api/vulnerabilities"
        output = self._get(url)
        if output:
            return output
        else:
            return False

    def get_machine_vulnerabilites(self):
        url = self._api_url + "/api/vulnerabilities/machinesVulnerabilities"
        output = self._get(url)
        if output:
            return output
        else:
            return False

    def get_vulnerabilites_by_machine(self, machineId):
        url = (
            self._api_url
            + f"/api/vulnerabilities/machinesVulnerabilities?$filter=machineId eq '{machineId}'"
        )
        output = self._get(url)
        if output:
            return output
        else:
            return False

    def get_vulnerabilites_by_id(self, cve):
        url = self._api_url + f"/api/vulnerabilities/{cve}"
        output = self._get(url)
        if output:
            return output
        else:
            return False

    def get_endpoints(self):
        url = self._api_url + "/api/machines"
        output = self._get(url)
        if output:
            return output
        else:
            return False

    def clean_health(self, endpoint):
        health = endpoint["healthStatus"]
        return health

    def get(self, api):
        url = self._api_url + api
        return self._get(url)

    def post(self, api, payload):
        url = self._api_url + api
        return self._post(url, payload)

    def kql_query(self, query):
        url = self._api_url + "/api/advancedqueries/run"
        payload = {"Query": query}
        return self._post(url, payload)