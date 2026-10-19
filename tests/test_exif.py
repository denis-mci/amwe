import struct

import httpx
import pytest

from amwe.collectors.exif import ExifCollector, gps_coordinates
from amwe.models import Severity, Target

IMAGE_URL = "https://example.com/me.jpg"


def rational_dms(degrees: int, minutes: int, seconds: int, endian: str = ">") -> bytes:
    return struct.pack(endian + "6I", degrees, 1, minutes, 1, seconds, 1)


def jpeg_with_gps(
    lat_ref: bytes, lat: bytes, lon_ref: bytes, lon: bytes, endian: str = ">"
) -> bytes:
    # TIFF layout: header (8), IFD0 with one GPS pointer (18), GPS IFD with four tags (54).
    gps_ifd, rationals = 26, 80
    ifd0 = struct.pack(endian + "HHHII", 1, 0x8825, 4, 1, gps_ifd) + struct.pack(endian + "I", 0)
    gps = struct.pack(endian + "H", 4)
    gps += struct.pack(endian + "HHI4s", 1, 2, 2, lat_ref + b"\x00\x00\x00")
    gps += struct.pack(endian + "HHII", 2, 5, 3, rationals)
    gps += struct.pack(endian + "HHI4s", 3, 2, 2, lon_ref + b"\x00\x00\x00")
    gps += struct.pack(endian + "HHII", 4, 5, 3, rationals + 24)
    gps += struct.pack(endian + "I", 0)
    byte_order = b"MM" if endian == ">" else b"II"
    tiff = byte_order + struct.pack(endian + "HI", 42, 8) + ifd0 + gps + lat + lon
    app1 = b"Exif\x00\x00" + tiff
    return b"\xff\xd8\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + b"\xff\xd9"


BERLIN = jpeg_with_gps(b"N", rational_dms(52, 31, 12), b"E", rational_dms(13, 24, 18))


def test_parses_northern_eastern_position():
    coordinates = gps_coordinates(BERLIN)
    assert coordinates is not None
    assert coordinates.latitude == pytest.approx(52.52)
    assert coordinates.longitude == pytest.approx(13.405)


def test_little_endian_south_and_west_are_negative():
    lat, lon = rational_dms(33, 52, 4, "<"), rational_dms(151, 12, 36, "<")
    jpeg = jpeg_with_gps(b"S", lat, b"W", lon, endian="<")
    coordinates = gps_coordinates(jpeg)
    assert coordinates is not None
    assert coordinates.latitude < 0
    assert coordinates.longitude < 0


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff\xda\x00\x02",
        BERLIN[:60],
    ],
    ids=["empty", "not-jpeg", "no-exif", "truncated"],
)
def test_missing_or_broken_exif_yields_none(data):
    assert gps_coordinates(data) is None


@pytest.mark.asyncio
async def test_reports_gps_finding(mock_http):
    mock_http(lambda request: httpx.Response(200, content=BERLIN))

    findings = [f async for f in ExifCollector().collect(Target("me@example.com", None, IMAGE_URL))]

    assert len(findings) == 1
    assert findings[0].kind == "gps"
    assert findings[0].value == "52.520000, 13.405000"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].url == IMAGE_URL


@pytest.mark.asyncio
async def test_unreachable_image_yields_nothing(mock_http):
    mock_http(lambda request: httpx.Response(404))

    findings = [f async for f in ExifCollector().collect(Target("me@example.com", None, IMAGE_URL))]

    assert findings == []


@pytest.mark.asyncio
async def test_no_image_url_yields_nothing():
    assert [f async for f in ExifCollector().collect(Target("me@example.com"))] == []
