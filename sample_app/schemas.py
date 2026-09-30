"""Validated response schemas exposed by the sample API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from sample_app.config import Environment


class ResponseModel(BaseModel):
    """Strict immutable base model for API responses."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )


class LivenessResponse(ResponseModel):
    """Response returned when the process is alive."""

    status: Literal["ok"] = "ok"


class ReadinessResponse(ResponseModel):
    """Response returned when the application is ready."""

    status: Literal["ready"] = "ready"


class ServiceInfoResponse(ResponseModel):
    """Public non-sensitive service information."""

    name: str
    version: str
    environment: Environment
