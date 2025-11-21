from __future__ import annotations

"""TLS metadata inspection (non-MITM) helper."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TLSMetadata:
    """TLS handshake metadata that can be logged without decryption."""

    server_name: str
    tls_version: str
    cipher_suite: str


class TLSMetadataInspector:
    """Simulates TLS ClientHello metadata inspection without decrypting payloads."""

    def inspect(self, server_name: str, tls_version: str | None = None) -> TLSMetadata:
        version = tls_version or "TLSv1.3"
        cipher_suite = "TLS_AES_256_GCM_SHA384"
        return TLSMetadata(server_name=server_name, tls_version=version, cipher_suite=cipher_suite)
