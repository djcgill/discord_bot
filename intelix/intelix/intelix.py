import base64
import json
import time
import requests

from http import HTTPStatus
from requests import Response

from urllib.parse import urlparse

from .client import Client
from .exceptions import InvalidRequestException, InvalidClientException, InvalidTokenException, UrlNotFound

'''
Want this implementation

scanner = IntelixScanner(client_id, client_secret)

url_scan = IntelixScanner(url=url, Id=uniqueid)
score = url.score
prod_cat = url.prod_cat

file_scan = scanner(file=content, id=uniqueid)
score = file_scan.score
satic_results = file_scan.static_scan()
'''

MAX_FILE_SIZE=4718592

class IntelixScanner:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

    def scan(self, **kwargs):
        correlationId = kwargs['id'] if kwargs['id'] else None

        #TODO: HAndle multiple files and urls
        if 'url' in kwargs:
            with Url(self.client_id, self.client_secret) as url_scanner:
                url_scanner.lookup(kwargs['url'], correlationId)
                return url_scanner
        elif 'file' in kwargs:
            with File(self.client_id, self.client_secret) as file_scanner:
                file_scanner.lookup(['file'], correlationId)
                return file_scanner


class File(Client):
    def __init__(self, **options):
        self.score = options.get('score', None)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type:
            print(f'exc_type: {exc_type}')
            print(f'exc_value: {exc_value}')
            print(f'exc_traceback: {exc_traceback}')

    def __enter__(self):
        return self

    def lookup(self, sha256: str, correlationId: str):
        if not self.token_valid:
            self._authenticate()

        lookup_url = f"{self.api_url_scheme}/lookup/files/v1/{sha256}"
        headers = {
            "Authorization": self.token,
            "X-Correlation-ID": correlationId
                   }

        lookup_response = requests.get(
            url = lookup_url,
            headers = headers
        )

        if lookup_response.status_code == HTTPStatus.OK:
            self.parse_lookup_result(lookup_response.content)
        elif lookup_response.status_code == HTTPStatus.UNAUTHORIZED:
            raise InvalidTokenException("Credentials not authorized for this service")
        elif lookup_response.status_code == HTTPStatus.NOT_FOUND:
            raise UrlNotFound('No data found for URL')
        else:
            raise NotImplementedError
            #TODO: AWS recomended eror retry

    def parse_lookup_result(self, lookup_json: bytes):
        result = json.loads(lookup_json.decode('utf-8'))

        try:
            self.score = int(result['reputationScore'])
            self.present = True
            if self.score < 20:
                self.risk_level = 'MALWARE'
            elif self.score < 30:
                self.risk_level = 'PUA'
            elif self.score < 70:
                self.risk_level = 'UNKNOWN'
        except KeyError:
            # If no score given assume first time file has been seen and set it UNKNOWN
            self.score = 31
            self.risk_level = 'UNKNOWN'
            self.present = False

        self.detection = result.get('detectionName', None)
        self.ttl = result.get('ttl', None)

    def _submit_for_analysis(self, file_content: bytes, scan_type: str, correlationId: str) -> Response:
        if not self.token_valid:
            self.authenticate

        #TODO: implement file size checking

        scan_url = f"{self.api_url_scheme}/analysis/file/{scan_type}/v1"
        headers = {
            "Authorization": self.token,
            "X-Correlation-ID": correlationId
                   }
        file = {'file': file_content}

        scan_response = requests.get(
            url = scan_url,
            headers = headers,
            files = file
        )

        return scan_response

    def scan_static(self):
        pass

    def scan_dynamic(self):
        pass

class Url(Client):
    def __init__(self, **options: dict):
        self.score = options.get('score', None)
        self.present = None

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type:
            print(f'exc_type: {exc_type}')
            print(f'exc_value: {exc_value}')
            print(f'exc_traceback: {exc_traceback}')

    def __enter__(self):
        return self

    def lookup(self, url: str, correlationId: str):
        url_domain = extract_domain(url)
        if not self.token_valid:
            self._authenticate()

        lookup_url = f"{self.api_url_scheme}/lookup/urls/{url_domain}"
        headers = {"Authorization": self.token,
                    "X-Correlation-ID": correlationId}

        lookup_response = requests.get(
            url = lookup_url,
            headers = headers
        )

        if lookup_response.status_code == HTTPStatus.OK:
            self.parse_lookup_result(lookup_response.content)
        elif lookup_response.status_code == HTTPStatus.UNAUTHORIZED:
            raise InvalidTokenException("Credentials not authorized for this service")
        elif lookup_response.status_code == HTTPStatus.NOT_FOUND:
            raise UrlNotFound('No data found for URL')
        else:
            raise NotImplementedError
            #TODO: AWS recomended eror retry


        @staticmethod
        def extract_domain(url: str) -> str:
            parsed_url = urlparse(url)
            return parsed_url.netloc

        def parse_lookup_result(self, lookup_json: bytes):
            result = json.loads(lookup_json.decode('utf-8'))

            self.risk_level = result.get('riskLevel', 'UNCLASSIFIED')
            self.prod_category = result.get('productivityCategory', 'PROD_UNCATEGORIZED')
            self.sec_category = result.get('secuirtyCategory', 'SEC_CATEGORIZED')
            self.ttl = result.get('ttl', None)

