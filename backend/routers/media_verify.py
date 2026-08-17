"""
routers/media_verify.py
------------------------
The S26 module's entry point: signature check + deepfake-likelihood scan
for a given filename, returned as a MediaVerifyResult. Moved out of
main.py verbatim — no logic changed, only relocated behind an APIRouter.

Deliberately stateless / no STORE access — this endpoint checks a piece
of media and returns a verdict; it does NOT create an alert on its own
(that composition happens in routers/alerts.py's /alerts/simulate, or
would happen in a future real media-upload route that calls this same
media_integrity_service.verify_media()).
"""

from fastapi import APIRouter

from models import MediaVerifyRequest, MediaVerifyResult
from services import media_integrity_service

router = APIRouter(tags=["media"])


@router.post("/media/verify", response_model=MediaVerifyResult)
def verify_media(req: MediaVerifyRequest):
    return media_integrity_service.verify_media(req)