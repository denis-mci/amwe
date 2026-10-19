"""EXIF collector — reads the GPS position embedded in a public JPEG.

Phone cameras write where a photo was taken into its EXIF block, and many sites
serve the original file untouched. Reading it takes one GET of the image. The
parser covers exactly the JPEG -> TIFF -> GPS path it needs, so no imaging
library is pulled in.
"""

from __future__ import annotations

import struct
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from amwe.collectors.base import register
from amwe.models import Finding, Severity, Target

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; amwe/0.1; +self-scan)"}
# EXIF sits in the APP1 segment, which JPEG caps at 64 KiB and places near the start.
_EXIF_WINDOW = 128 * 1024

_SOI = b"\xff\xd8"
_APP1 = b"\xff\xe1"
_SOS = b"\xff\xda"
_EXIF_HEADER = b"Exif\x00\x00"
_BYTE_ORDERS = {b"II": "<", b"MM": ">"}
_GPS_IFD_POINTER = 0x8825
_GPS_LATITUDE_REF, _GPS_LATITUDE, _GPS_LONGITUDE_REF, _GPS_LONGITUDE = 1, 2, 3, 4


@dataclass(frozen=True, slots=True)
class Coordinates:
    """A position in decimal degrees; south and west are negative."""

    latitude: float
    longitude: float

    def __str__(self) -> str:
        return f"{self.latitude:.6f}, {self.longitude:.6f}"


class ExifCollector:
    name = "exif"

    async def collect(self, target: Target) -> AsyncIterator[Finding]:
        if target.image_url is None:
            return
        head = await _fetch_head(target.image_url)
        coordinates = gps_coordinates(head) if head else None
        if coordinates is None:
            return
        yield Finding(
            source=self.name,
            kind="gps",
            value=str(coordinates),
            severity=Severity.HIGH,
            url=target.image_url,
        )


async def _fetch_head(url: str) -> bytes | None:
    try:
        async with (
            httpx.AsyncClient(timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True) as client,
            client.stream("GET", url) as response,
        ):
            if response.status_code != 200:
                return None
            head = bytearray()
            async for chunk in response.aiter_bytes():
                head += chunk
                if len(head) >= _EXIF_WINDOW:
                    break
            return bytes(head)
    except httpx.HTTPError:
        return None


def gps_coordinates(jpeg: bytes) -> Coordinates | None:
    """Return the GPS position stored in the EXIF block of ``jpeg``, if any."""
    tiff = _exif_tiff(jpeg)
    if tiff is None:
        return None
    try:
        return _Tiff.parse(tiff).gps()
    except (struct.error, IndexError, KeyError, ZeroDivisionError):
        return None


def _exif_tiff(jpeg: bytes) -> bytes | None:
    if not jpeg.startswith(_SOI):
        return None
    offset = len(_SOI)
    while offset + 4 <= len(jpeg):
        marker = jpeg[offset : offset + 2]
        if marker[0] != 0xFF or marker == _SOS:
            return None
        (length,) = struct.unpack_from(">H", jpeg, offset + 2)
        segment = jpeg[offset + 4 : offset + 2 + length]
        if marker == _APP1 and segment.startswith(_EXIF_HEADER):
            return segment[len(_EXIF_HEADER) :]
        offset += 2 + length
    return None


@dataclass(frozen=True, slots=True)
class _Tiff:
    data: bytes
    order: str

    @classmethod
    def parse(cls, data: bytes) -> _Tiff:
        return cls(data, _BYTE_ORDERS[data[:2]])

    def gps(self) -> Coordinates | None:
        ifd0 = self._entries(self._u32(4))
        if _GPS_IFD_POINTER not in ifd0:
            return None
        gps = self._entries(self._u32(ifd0[_GPS_IFD_POINTER]))
        if not {_GPS_LATITUDE_REF, _GPS_LATITUDE, _GPS_LONGITUDE_REF, _GPS_LONGITUDE} <= gps.keys():
            return None
        latitude = self._degrees(
            gps[_GPS_LATITUDE], negative=self._ref(gps[_GPS_LATITUDE_REF]) == "S"
        )
        longitude = self._degrees(
            gps[_GPS_LONGITUDE], negative=self._ref(gps[_GPS_LONGITUDE_REF]) == "W"
        )
        return Coordinates(latitude, longitude)

    def _entries(self, ifd_offset: int) -> dict[int, int]:
        """Map each tag of the IFD to the position of its 4-byte value field."""
        (count,) = struct.unpack_from(self.order + "H", self.data, ifd_offset)
        entries: dict[int, int] = {}
        for index in range(count):
            entry = ifd_offset + 2 + 12 * index
            (tag,) = struct.unpack_from(self.order + "H", self.data, entry)
            entries[tag] = entry + 8
        return entries

    def _u32(self, position: int) -> int:
        value: int = struct.unpack_from(self.order + "I", self.data, position)[0]
        return value

    def _ref(self, value_field: int) -> str:
        return chr(self.data[value_field])

    def _degrees(self, value_field: int, *, negative: bool) -> float:
        # Three RATIONALs (degrees, minutes, seconds), too large to sit inline.
        parts: tuple[int, ...] = struct.unpack_from(
            self.order + "6I", self.data, self._u32(value_field)
        )
        degrees, minutes, seconds = (
            numerator / denominator
            for numerator, denominator in zip(parts[::2], parts[1::2], strict=True)
        )
        value = degrees + minutes / 60 + seconds / 3600
        return -value if negative else value


register(ExifCollector())
