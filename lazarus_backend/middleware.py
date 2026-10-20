from __future__ import annotations
from typing import Callable
from django.http import HttpRequest, HttpResponse


class LazarusCORSMiddleware:
    """
    Lightweight CORS middleware allowing the Lazarus React frontend (Vite dev server
    or production build) to communicate with `/api/v1/*`, `/api/docs/`, and `/api/redoc/`.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.method == "OPTIONS":
            response = HttpResponse(status=204)
        else:
            response = self.get_response(request)

        origin = request.headers.get("Origin", "*")
        response["Access-Control-Allow-Origin"] = origin if origin else "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, Accept, X-Requested-With"
        )
        response["Access-Control-Expose-Headers"] = "X-Cache, Retry-After"
        return response
