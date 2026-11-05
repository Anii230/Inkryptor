"""LSB steganography decoder for Inkryptor."""

import struct
import warnings
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from inkryptor.embed import (
    MAGIC,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAX_IMAGE_PIXELS,
)


class ExtractionError(Exception):
    """Raised when payload extraction fails."""


def _decode_bytes(
    pixel_data: bytes,
    start_bit: int,
    byte_count: int,
) -> bytes:
    """Decode bytes from RGB channel least significant bits."""

    if start_bit < 0 or byte_count < 0:
        raise ExtractionError("Invalid payload boundaries.")

    required_bits = byte_count * 8

    if start_bit + required_bits > len(pixel_data):
        raise ExtractionError(
            "Payload extends beyond available image data."
        )

    result = bytearray()

    for byte_index in range(byte_count):
        value = 0

        for bit_offset in range(8):
            channel_index = start_bit + byte_index * 8 + bit_offset

            bit = pixel_data[channel_index] & 1
            value = (value << 1) | bit

        result.append(value)

    return bytes(result)


def extract_payload(image_path: str | Path) -> bytes:
    """
    Extract a framed binary payload from an Inkryptor stego image.

    Validates image dimensions, magic identifier and payload length.
    """

    image_path = Path(image_path).expanduser()
    rgb_image = None

    try:
        with warnings.catch_warnings():
            warnings.simplefilter(
                "error",
                Image.DecompressionBombWarning,
            )

            with Image.open(image_path) as image:
                width, height = image.size

                if width <= 0 or height <= 0:
                    raise ExtractionError("Invalid image dimensions.")

                if width * height > MAX_IMAGE_PIXELS:
                    raise ExtractionError(
                        "Image exceeds the maximum supported size "
                        f"of {MAX_IMAGE_PIXELS:,} pixels."
                    )

                image.load()
                rgb_image = image.convert("RGB")

    except ExtractionError:
        raise

    except (
        OSError,
        ValueError,
        UnidentifiedImageError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise ExtractionError(
            "Unable to open or process the image."
        ) from exc

    try:
        pixel_data = rgb_image.tobytes()

        # Every RGB channel contributes exactly ONE LSB.
        total_bits = len(pixel_data)

        header_bits = HEADER_SIZE * 8

        if total_bits < header_bits:
            raise ExtractionError(
                "Image is too small to contain a header."
            )

        header = _decode_bytes(
            pixel_data,
            start_bit=0,
            byte_count=HEADER_SIZE,
        )

        try:
            magic, payload_length = struct.unpack(
                HEADER_FORMAT,
                header,
            )

        except struct.error as exc:
            raise ExtractionError(
                "Invalid payload header."
            ) from exc

        if magic != MAGIC:
            raise ExtractionError(
                "No valid Inkryptor payload found in this image."
            )

        available_bits = total_bits - header_bits
        available_bytes = available_bits // 8

        if payload_length > available_bytes:
            raise ExtractionError(
                "Declared payload length exceeds image capacity. "
                "The image may be corrupted."
            )

        return _decode_bytes(
            pixel_data,
            start_bit=header_bits,
            byte_count=payload_length,
        )

    finally:
        rgb_image.close()
