"""Provision initial asymmetric keys and a short-lived agent JWT for local setup."""

import argparse
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lloydsagent.cra_gateway_auth import (
    AGENT_AUDIENCE,
    AGENT_ISSUER,
    CREDIT_REPORT_SCOPE,
    MORTGAGE_ASSESS_SCOPE,
)


def _write_new_file(path: Path, contents: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as file_handle:
        file_handle.write(contents)


def _private_key_pair(directory: Path, prefix: str) -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_new_file(directory / f"{prefix}_private_key.pem", private_bytes, 0o600)
    _write_new_file(directory / f"{prefix}_public_key.pem", public_bytes, 0o644)
    return private_bytes, public_bytes


def provision(directory: Path, valid_hours: int) -> None:
    if not 1 <= valid_hours <= 24:
        raise ValueError("valid_hours must be between 1 and 24.")
    directory.mkdir(parents=True, exist_ok=True)
    agent_private_key, _ = _private_key_pair(directory, "cra_agent")
    _private_key_pair(directory, "cra_gateway")

    issued_at = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": AGENT_ISSUER,
            "aud": AGENT_AUDIENCE,
            "sub": "keystone-mortgage-agent",
            "scope": [CREDIT_REPORT_SCOPE, MORTGAGE_ASSESS_SCOPE],
            "iat": issued_at,
            "exp": issued_at + timedelta(hours=valid_hours),
            "jti": str(uuid.uuid4()),
        },
        agent_private_key,
        algorithm="RS256",
    )
    _write_new_file(directory / "cra_agent_token.jwt", token.encode("ascii"), 0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("security") / "secrets")
    parser.add_argument("--valid-hours", type=int, default=12)
    arguments = parser.parse_args()
    provision(arguments.directory, arguments.valid_hours)
    print(f"Gateway credentials created in {arguments.directory.resolve()}.")
    print("Protect private keys and the token; the agent private key is provisioning-only.")
    print("Provision TLS certificates separately with your trusted internal CA.")


if __name__ == "__main__":
    main()
