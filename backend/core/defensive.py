from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, HTTPException
from db.database import log_security_event

limiter = Limiter(key_func=get_remote_address)

async def check_abuse(request: Request):
    """
    Ek güvenlik kontrolleri: Anormal trafik patternlerini algılar.
    """
    ip = get_remote_address(request)
    # Gelecekte buraya daha karmaşık pattern algılama eklenebilir.
    # Şimdilik sadece loglama yapıyoruz.
    return True

async def abuse_handler(request: Request, exc: Exception):
    ip = get_remote_address(request)
    await log_security_event(
        ip=ip,
        action="RATE_LIMIT_EXCEEDED",
        details=f"IP {ip} hız sınırını aştı.",
        severity="WARNING"
    )
    raise HTTPException(status_code=429, detail="Çok fazla istek gönderildi. Lütfen bekleyin.")
