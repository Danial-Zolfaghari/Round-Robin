"""Active validation: TCP / TLS(SNI) / optional HTTP Host — evidence only, no guesses."""

from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any

from ..failures import FailureSink
from ..models import ValidationResult, utc_now_iso
from ..rate_limit import RateLimiter


class ActiveValidator:
    def __init__(
        self,
        rate_limiter: RateLimiter,
        failures: FailureSink,
        tcp_timeout: float = 5.0,
        tls_timeout: float = 8.0,
        do_http: bool = False,
        semaphore: asyncio.Semaphore | None = None,
        rps: float = 4.0,
    ) -> None:
        self.rate = rate_limiter
        self.failures = failures
        self.tcp_timeout = tcp_timeout
        self.tls_timeout = tls_timeout
        self.do_http = do_http
        self.sem = semaphore or asyncio.Semaphore(8)
        self.rate.named("validate", rps)

    async def validate(self, hostname: str, ip: str) -> ValidationResult:
        async with self.sem:
            await self.rate.acquire(named="validate", hostname=hostname, source="validation")
            result = ValidationResult(timestamp=utc_now_iso(), details={})
            result.tcp_443 = await self._tcp_connect(ip, 443)
            result.details["tcp_443"] = {"reachable": result.tcp_443}

            if result.tcp_443:
                tls_info = await self._tls_handshake(ip, hostname)
                result.tls = tls_info.get("ok")
                result.tls_hostname_match = tls_info.get("hostname_match")
                result.details["tls"] = tls_info
            else:
                result.tls = False
                result.tls_hostname_match = False
                result.details["tls"] = {"ok": False, "reason": "tcp_443_failed"}

            if self.do_http:
                result.tcp_80 = await self._tcp_connect(ip, 80)
                if result.tcp_80:
                    http_info = await self._http_probe(ip, hostname, 80)
                    result.http = http_info.get("ok")
                    result.http_host_match = http_info.get("host_match")
                    result.details["http"] = http_info
                else:
                    result.http = False
                    result.http_host_match = False
                    result.details["http"] = {"ok": False, "reason": "tcp_80_failed"}

                # Also try HTTPS GET if TLS worked
                if result.tls:
                    https_info = await self._http_probe(ip, hostname, 443, tls=True)
                    result.details["https"] = https_info
                    if https_info.get("ok"):
                        result.http = True
                        if https_info.get("host_match"):
                            result.http_host_match = True

            return result

    async def _tcp_connect(self, ip: str, port: int) -> bool:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.tcp_timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception as e:
            self.failures.record(
                "validation",
                f"tcp:{port}",
                e,
                error_type=type(e).__name__,
            )
            return False

    async def _tls_handshake(self, ip: str, hostname: str) -> dict[str, Any]:
        ctx = ssl.create_default_context()
        # We want to know if cert matches hostname — use check_hostname
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=hostname),
                timeout=self.tls_timeout,
            )
            sslobj = writer.get_extra_info("ssl_object")
            cert = sslobj.getpeercert() if sslobj else None
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {
                "ok": True,
                "hostname_match": True,
                "peer_cert_subject": _cert_subject(cert) if cert else None,
                "note": "TLS handshake succeeded with SNI + hostname verification",
            }
        except ssl.SSLCertVerificationError as e:
            # TCP+TLS may work but name mismatch / invalid cert
            # Retry without hostname check to distinguish reachability vs name match
            insecure = await self._tls_insecure(ip, hostname)
            self.failures.record("validation", "tls_verify", e, hostname=hostname, error_type="TLSCertVerify")
            return {
                "ok": insecure.get("tls_raw_ok", False),
                "hostname_match": False,
                "error_type": "SSLCertVerificationError",
                "message": str(e),
                "insecure_probe": insecure,
            }
        except Exception as e:
            self.failures.record("validation", "tls", e, hostname=hostname)
            return {"ok": False, "hostname_match": False, "error_type": type(e).__name__, "message": str(e)}

    async def _tls_insecure(self, ip: str, hostname: str) -> dict[str, Any]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=hostname),
                timeout=self.tls_timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"tls_raw_ok": True, "note": "TLS connected without certificate verification"}
        except Exception as e:
            return {"tls_raw_ok": False, "error_type": type(e).__name__, "message": str(e)}

    async def _http_probe(self, ip: str, hostname: str, port: int, tls: bool = False) -> dict[str, Any]:
        # Minimal raw HTTP to avoid SSRF via redirects to odd schemes — we connect to IP only.
        try:
            if tls:
                ctx = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ctx, server_hostname=hostname),
                    timeout=self.tls_timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.tcp_timeout,
                )
            req = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: dns-discovery-engine/2.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(req.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=self.tcp_timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            text = data.decode(errors="ignore")
            status_line = text.split("\r\n", 1)[0] if text else ""
            ok = status_line.startswith("HTTP/")
            return {
                "ok": ok,
                "host_match": ok,  # we sent Host header; response received from IP with that Host
                "status_line": status_line[:200],
                "note": "Response received after connecting to candidate IP with Host/SNI=target hostname",
            }
        except Exception as e:
            self.failures.record("validation", f"http:{port}", e, hostname=hostname)
            return {"ok": False, "host_match": False, "error_type": type(e).__name__, "message": str(e)}


def _cert_subject(cert: dict[str, Any] | None) -> str | None:
    if not cert:
        return None
    subject = cert.get("subject") or ()
    for rdn in subject:
        for attr in rdn:
            if attr and attr[0] == "commonName":
                return str(attr[1])
    return None
