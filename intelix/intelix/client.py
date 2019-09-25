import base64
import json
import time
import requests

from http import HTTPStatus

from .exceptions import InvalidRequestException, InvalidClientException, InvalidTokenException, UrlNotFound


class Client:
    """Class to handle intelix requests"""
    def __init__(self, client_id=None, client_secret=None):
        if client_id and client_secret:
            self.basic_auth = base64.b64encode(bytes(f"{client_id}:{client_secret}", 'utf-8'))
        else:
            raise ValueError("Client ID with corresponding secret needed")

        self.api_url_scheme = "https://de.api.labs.sophos.com"
        self.auth_timestamp = None
        self.token = None
        self.token_valid  = self._token_valid
        self._authenticate()

    def _authenticate(self):
        token_url = f"{self.api_url_scheme}/oauth2/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': f'Basic {self.basic_auth.decode("utf-8")}'}
        data = {'grant_type': 'client_credentials'}

        response = requests.post(url=token_url, headers=headers, data=data)

        if response.status_code == HTTPStatus.OK:
            self.token, self.ttl = self.parse_access_token(response.content)
            self.auth_timestamp = time.time()
        elif response.status_code == HTTPStatus.BAD_REQUEST:
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
        # Assume is no timestamp don't need refresh
        if self.auth_timestamp is None:
            return True

        delta = time.time() - self.auth_timestamp
        return delta < 3600

    def _determine_region(self):
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