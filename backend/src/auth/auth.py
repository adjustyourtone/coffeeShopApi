import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'dev-bdz6mf42.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'http://localhost:5000'  # unique identifier
CLIENT_ID = 'CIO10DeUKgjuNjUna85xtNt4DEWY2nmO'


class AuthError(Exception):
    def __init__(self, error, status_code):
        """Defines an Authentiation Error."""
        self.error = error
        self.status_code = status_code


def get_token_auth_header():
    """This returns a token from a header in a request."""
    # get the Authorization headers
    auth_header = request.headers.get("Authorization", None)
    if not auth_header:
        raise AuthError({"code": "missing_authorization_header",
                         "description":
                         "Authorization header is missing"}, 401)
    header_parts = auth_header.split(' ')

    # make sure header is in the correct format
    if len(header_parts) != 2 or not header_parts:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be formatted correctly'
            ' Bearer token'}, 401)

    # make sure header includes bearer
    elif header_parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with the bearer'}, 401)

    return header_parts[1]


def check_permissions(permission, payload):
    """Verifies that the correct permissions are included to access an endpoint."""
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'You do not have permission to access this data.'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'You do not possess the correct permissions.',
        }, 401)
    return True


def verify_decode_jwt(token):
    """This will decode a a token."""
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
        'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
    }, 400)


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        """This will pass the decoded payload if the permissions have been verfied."""
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
