import base64
import json
import time
import requests

from http import HTTPStatus
from urllib.parse import urlparse

from .exceptions import (
    InvalidRequestException, InvalidClientException, InvalidTokenException, UrlNotFound)

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

class IntelixObject:
    """Class to handle intelix requests"""
    def __init__(self, client_id=None, client_secret=None):
        if client_id and client_secret:
            self.basic_auth = base64.b64encode(bytes(f"{client_id}:{client_secret}", 'utf-8'))
        else:
            raise ValueError("Client ID with corresponding secret needed")

        self.api_url_scheme = "https://de.api.labs.sophos.com"
        self.auth_timestamp = None
        self.access_token = None
        self.token  = self._token_valid
        self.authenticate()

    def authenticate(self):
        token_url = f"{self.api_url_scheme}/oauth2/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': f'Basic {self.basic_auth.decode("utf-8")}'}
        data = {'grant_type': 'client_credentials'}

        response = requests.post(url=token_url, headers=headers, data=data)

        if response.status_code == 200:
            self.access_token, self.ttl = self.parse_access_token(response.content)
            self.auth_timestamp = time.time()
        elif response.status_code == 400:
            error = self.get_auth_error(response.content)
            if error == 'invalid_request':
                raise InvalidRequestException
            elif error == 'ivalid_client':
                raise InvalidClientException
            elif error == 'invalidToken':
                raise InvalidTokenException
            else:
                raise Exception(f'Unkown authentication error: {error}')
        else:
            raise Exception(f'Unkown Error: {response.text}')

    def _token_valid(self):
        delta = time.time() - self.auth_timestamp
        return delta < 3600

    def determine_region(self):
        # Find out which region to use for URL
        #boto? metadata?
        raise NotImplementedError

    @staticmethod
    def parse_access_token(auth_json: bytes) -> tuple:
        parsed_json = json.loads(auth_json)
        return parsed_json['access_token'], int(parsed_json['expires_in'])

    @staticmethod
    def get_auth_error(auth_json: bytes) -> int:
        parsed_json = json.loads(auth_json)
        return parsed_json['error']


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


class File(IntelixObject):
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
            self.authenticate()

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


    def scan_static(self):
        pass

    def scan_dynamic(self):
        pass

class Url(IntelixObject):
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
            self.authenticate()

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

        @staticmethod
        def parse_lookup_result(lookup_json: bytes):
            result = json.loads(lookup_json.decode('utf-8'))

            self.risk_level = result.get('riskLevel', 'UNCLASSIFIED')
            self.prod_category = result.get('productivityCategory', 'PROD_UNCATEGORIZED')
            self.sec_category = result.get('secuirtyCategory', 'SEC_CATEGORIZED')
            self.ttl = result.get('ttl', None)

