import base64
import json
import time
import requests

from urllib.parse import urlparse

class InvalidRequestException(Exception):
    pass


class InvalidClientException(Exception):
    pass


class InvalidTokenException(Exception):
    pass


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

    def token_valid(self):
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


class IntelixScanner(IntelixObject):
    def get_score(**kwargs):
        if 'url' in kwargs:
            with Url as url_scanner:
                url_scanner.lookup(kwargs['url'])
                return url_scanner
        elif 'file' in kwargs:
            with File as file_scanner:
                file_scanner.lookup(['file'])
                return file_scanner

    def lookup(sha256: str) -> dict:
        pass

    def scan_static(self):
        pass

    def scan_dynamic(self):
        pass

class File(IntelixScanner):
    def __init__(self, **options):
        self.score = options.get('score', None)

class Url(IntelixScanner):
    def __init__(self, **options):
        self.score = options.get('score', None)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type:
            print(f'exc_type: {exc_type}')
            print(f'exc_value: {exc_value}')
            print(f'exc_traceback: {exc_traceback}')

    def lookup(url: str) -> dict:
        pass


def extract_domain(url: str) -> str:
    parsed_url = urlparse(url)
    return parsed_url.netloc
