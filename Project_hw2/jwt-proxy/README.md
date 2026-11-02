# JWT Authentication Proxy

This project adds JWT authentication to a service (Legacy) that does not have its own authentication system. It uses **Envoy** as a reverse proxy and **go-httpbin** as the backend service. Everything runs using Docker Compose.

## How it works

```text
Client → Port 80 → Envoy → JWT validation → go-httpbin:8081
```

1. The client sends a request with a token in the `Authorization: Bearer <token>` header.
2. Envoy checks the token's signature, issuer, audience, and validity period. An expiration time is required.
3. If the token is valid, Envoy forwards the request to go-httpbin and returns its response.
4. If the token is missing or invalid, Envoy rejects the request.

Docker maps host port **80** to Envoy's container port **10000**. The backend runs on port **8081**, which is not published to the host. It is connected only to a private backend network, so external clients cannot bypass Envoy and access it directly.

## Project files

- `compose.yaml`: defines the containers, ports, and networks.
- `envoy.yaml`: configures request routing and JWT validation.
- `tools/manage.py`: generates signing keys, creates tokens, and tests the project.
- `tools/Dockerfile`: builds the Python tools container.
- `tools/requirements.txt`: lists the Python dependencies.
- `secrets/`: stores the generated private signing key.
- `public/`: stores the public verification key in JWKS format.

Tokens are signed using **RS256**. The tools container uses the private key to create tokens. Envoy receives only the public key to verify them. After successful validation, Envoy removes the token before forwarding the request.

## Requirements

- Docker and Docker Compose. On Windows, start Docker Desktop in Linux containers mode.
- Internet access for the initial downloads.
- Port 80 available on your computer.

Run the following commands from the folder containing `compose.yaml`.

## Setup

Build the tools and generate the keys:

```sh
docker compose build tools
docker compose run --rm tools init
```

Validate the configuration:

```sh
docker compose config --quiet
docker compose run --rm --no-deps envoy --mode validate -c /etc/envoy/envoy.yaml
```

Start the proxy and backend:

```sh
docker compose up -d envoy httpbin
```

## Automated tests

```sh
docker compose run --rm tools test
```

The tests check that:

- Missing, malformed, expired, modified, and incorrectly signed tokens are rejected.
- Tokens with an incorrect issuer or audience are rejected.
- Tokens without an expiration or with a future start time are rejected.
- Valid GET and POST requests reach the backend correctly.
- The token is removed before the request reaches the backend.
- Backend response status codes are preserved.
- The backend is unreachable from the frontend test container.

Expected result: **all 15 checks pass**. A wrong audience returns **403**; the other tested token failures return **401**.

## Manual test with PowerShell

A request without a token should return `401 Unauthorized`:

```powershell
curl.exe -i http://localhost/get
```

Generate a valid token and send an authenticated request:

```powershell
$token = (docker compose run --rm -T tools token | Select-Object -Last 1).Trim()
curl.exe -i -H "Authorization: Bearer $token" "http://localhost/get?course=internet"
```

This should return `200 OK` and a JSON response from go-httpbin. The token expires after 15 minutes; generate a new one when needed.

To check that the backend has no published port:

```sh
docker compose ps
docker compose port httpbin 8081
```

Only Envoy should have a published port. The second command should report no port mapping.

## Logs and shutdown

View logs:

```sh
docker compose logs envoy httpbin
```

Stop and remove the containers and networks:

```sh
docker compose down
```

The generated keys remain on disk. Restart Envoy after changing its configuration or public key:

```sh
docker compose restart envoy
```

## Notes

This project generates test tokens locally; it does not implement a login service. Keep the private key out of Git and never share it.

The project uses HTTP on port 80 for the assignment. JWT validation controls access, but HTTP does not encrypt the token during transmission. For real internet deployment, configure HTTPS with TLS termination at Envoy.

