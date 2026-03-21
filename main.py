"""
NL2Firewall — entry point.

Run locally:
    python main.py

Or with uvicorn directly:
    uvicorn app.api.main:app --reload --port 8000

With Docker Compose:
    cd docker && docker-compose up
"""

import uvicorn
from app.core.config import get_settings


if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "app.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
