# -*- coding: utf-8 -*-

"""Wrapper for the PrivateBin API."""

from privatebinapi.deletion import delete, delete_async
from privatebinapi.download import get, get_async
from privatebinapi.exceptions import (
    BadAuthConfigError,
    BadCompressionTypeError,
    BadExpirationTimeError,
    BadFormatError,
    PrivateBinAPIError,
    BadServerResponseError,
    UnsupportedFeatureError,
)
from privatebinapi.upload import send, send_async

__all__ = (
    "delete",
    "delete_async",
    "get",
    "get_async",
    "send",
    "send_async",
    "BadAuthConfigError",
    "BadCompressionTypeError",
    "BadExpirationTimeError",
    "BadFormatError",
    "BadServerResponseError",
    "PrivateBinAPIError",
    "UnsupportedFeatureError",
)

__author__ = "Pioverpie"
