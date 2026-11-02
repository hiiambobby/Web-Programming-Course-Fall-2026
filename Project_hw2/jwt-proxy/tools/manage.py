"""Local lab key generation, token issuance, and integration checks."""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PRIVATE = Path('/secrets/private.pem')
PUBLIC = Path('/public/jwks.json')
ISSUER = 'https://jwt-proxy.local'
AUDIENCE = 'legacy-httpbin'
KID = 'lab-rsa-key'
HTTP = build_opener(ProxyHandler({}))


def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def init():
    PRIVATE.parent.mkdir(parents=True, exist_ok=True)
    PUBLIC.parent.mkdir(parents=True, exist_ok=True)
    if PRIVATE.exists():
        key = serialization.load_pem_private_key(PRIVATE.read_bytes(), password=None)
        print('Keeping existing private key.')
    else:
        key = generate_key()
        data = key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
        # Exclusive creation prevents accidentally overwriting an existing key.
        with PRIVATE.open('xb') as file:
            file.write(data)
        os.chmod(PRIVATE, 0o600)
        print('Generated private signing key.')
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update(kid=KID, use='sig', alg='RS256')
    PUBLIC.write_text(json.dumps({'keys': [public]}, indent=2) + '\n')
    print('Wrote public JWKS. Envoy never receives the private key.')


def token(case='valid', subject='student', seconds=900):
    now = int(time.time())
    claims = dict(iss=ISSUER, aud=AUDIENCE, sub=subject,
                  iat=now, nbf=now - 1, exp=now + seconds)
    if case == 'expired':
        claims.update(iat=now - 600, nbf=now - 600, exp=now - 300)
    elif case == 'wrong-issuer':
        claims['iss'] = 'https://untrusted.local'
    elif case == 'wrong-audience':
        claims['aud'] = 'another-service'
    elif case == 'no-exp':
        del claims['exp']
    elif case == 'future':
        claims['nbf'] = now + 300
    key = generate_key() if case == 'wrong-key' else PRIVATE.read_bytes()
    encoded = jwt.encode(claims, key, algorithm='RS256', headers={'kid': KID})
    if case == 'tampered':
        header, payload, signature = encoded.split('.')
        claims['sub'] = 'attacker'
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        encoded = '.'.join([header, payload, signature])
    return encoded


def request(base, path, credential=None, method='GET', data=None):
    headers = {}
    if credential:
        headers['Authorization'] = 'Bearer ' + credential
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = Request(base + path, headers=headers, method=method, data=data)
    try:
        with HTTP.open(req, timeout=5) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()


def test(base):
    # Wait for the listener AND its upstream, not just container startup.
    valid = token()
    for attempt in range(30):
        try:
            if request(base, '/get', valid)[0] == 200:
                break
        except (URLError, OSError):
            pass
        time.sleep(1)
    else:
        raise RuntimeError('Proxy/backend not ready. Check docker compose logs.')
    failures = []

    def check(name, condition):
        print(('PASS' if condition else 'FAIL') + ': ' + name)
        if not condition:
            failures.append(name)

    check('missing token rejected', request(base, '/get')[0] == 401)
    check('malformed token rejected', request(base, '/get', 'not.a.jwt')[0] == 401)
    for case in ['expired', 'wrong-key', 'wrong-issuer', 'wrong-audience',
                 'no-exp', 'future', 'tampered']:
        expected = 403 if case == 'wrong-audience' else 401
        check(case + ' token rejected', request(base, '/get', token(case))[0] == expected)
    status, body = request(base, '/get?course=internet', valid)
    result = json.loads(body)
    check('valid GET and query forwarded', status == 200 and result['args']['course'] == ['internet'])
    check('JWT removed before forwarding', not any(k.lower() == 'authorization' for k in result['headers']))
    status, body = request(base, '/post', valid, 'POST', b'{"message":"hello"}')
    check('POST method and JSON body forwarded', status == 200 and json.loads(body)['json'] == {'message': 'hello'})
    check('POST without token rejected', request(base, '/post', method='POST', data=b'{}')[0] == 401)
    check('backend status preserved', request(base, '/status/418', valid)[0] == 418)
    # Tools is attached only to frontend; httpbin is attached only to backend.
    try:
        with socket.create_connection(('httpbin', 8081), timeout=2):
            reachable = True
    except OSError:
        reachable = False
    check('backend unreachable from frontend test container', not reachable)
    if failures:
        raise SystemExit(f'{len(failures)} checks failed')
    print('All integration checks passed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    issue = sub.add_parser('token')
    issue.add_argument('--case', default='valid', choices=['valid', 'expired', 'wrong-key',
                       'wrong-issuer', 'wrong-audience', 'no-exp', 'future', 'tampered'])
    issue.add_argument('--subject', default='student')
    issue.add_argument('--seconds', type=int, default=900)
    tests = sub.add_parser('test')
    tests.add_argument('--base-url', default='http://envoy:10000')
    args = parser.parse_args()
    if args.command == 'init':
        init()
    elif args.command == 'token':
        print(token(args.case, args.subject, args.seconds))
    else:
        test(args.base_url.rstrip('/'))


if __name__ == '__main__':
    main()
