"""Active validation: TCP / TLS(SNI) / optional HTTP Host — evidence only, no guesses."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

from ..failures import FailureSink
from ..models import ValidationResult, utc_now_iso
from ..rate_limit import RateLimiter


class ActiveValidator:
    def __init__(self, rate_limiter: RateLimiter, failures: FailureSink, tcp_timeout: float = 5.0, tls_timeout: float = 8.0, do_http: bool = False, semaphore: asyncio.Semaphore | None = None, rps: float = 4.0) -> None:
        self.rate=rate_limiter; self.failures=failures; self.tcp_timeout=tcp_timeout; self.tls_timeout=tls_timeout; self.do_http=do_http; self.sem=semaphore or asyncio.Semaphore(8); self.rate.named("validate",rps)

    async def validate(self, hostname: str, ip: str) -> ValidationResult:
        async with self.sem:
            await self.rate.acquire(named="validate",hostname=hostname,source="validation")
            result=ValidationResult(timestamp=utc_now_iso(),details={})
            result.tcp_443=await self._tcp_connect(ip,443)
            if result.tcp_443:
                tls=await self._tls_handshake(ip,hostname); result.tls=tls.get("ok"); result.tls_hostname_match=tls.get("hostname_match"); result.details["tls"]=tls
            else:
                result.tls=False; result.tls_hostname_match=False
            return result

    async def _tcp_connect(self, ip: str, port: int) -> bool:
        try:
            reader,writer=await asyncio.wait_for(asyncio.open_connection(ip,port),timeout=self.tcp_timeout); writer.close(); await writer.wait_closed(); return True
        except Exception as e:
            self.failures.record("validation",f"tcp:{port}",e); return False

    async def _tls_handshake(self, ip: str, hostname: str) -> dict[str,Any]:
        ctx=ssl.create_default_context(); ctx.check_hostname=True; ctx.verify_mode=ssl.CERT_REQUIRED
        try:
            reader,writer=await asyncio.wait_for(asyncio.open_connection(ip,443,ssl=ctx,server_hostname=hostname),timeout=self.tls_timeout); writer.close(); await writer.wait_closed(); return {"ok":True,"hostname_match":True}
        except ssl.SSLCertVerificationError as e:
            self.failures.record("validation","tls_verify",e,hostname=hostname,error_type="TLSCertVerify"); return {"ok":False,"hostname_match":False,"error_type":"TLSCertVerify"}
        except Exception as e:
            self.failures.record("validation","tls",e,hostname=hostname); return {"ok":False,"hostname_match":False,"error_type":type(e).__name__}
