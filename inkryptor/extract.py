"""LSB steganography decoder for Inkryptor."""

import struct
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from inkryptor.embed import MAGIC, HEADER_FORMAT, HEADER_SIZE


class ExtractionError(Exception):
    """Raised when payload extraction fails."""


def _decode_bytes(
    pixel_data: bytes,
    start_bit: int,
    byte_count: int,
) -> bytes:
    """Decode bytes from RGB channel least significant bits."""

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

    Validates the magic identifier and declared payload length.
    """

    try:
        with Image.open(image_path) as image:
            image.load()
            rgb_image = image.convert("RGB")

    except (OSError, UnidentifiedImageError) as exc:
        raise ExtractionError("Unable to open the image.") from exc

    try:
        pixel_data = rgb_image.tobytes()

        total_bits = len(pixel_data) * 8

        header_bits = HEADER_SIZE * 8

        if total_bits < header_bits:
            raise ExtractionError("Image is too small to contain a header.")

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
            raise ExtractionError("Invalid payload header.") from exc

        if magic != MAGIC:
            raise ExtractionError(
                "No valid Inkryptor payload found in this image."
            )

        available_bits = total_bits - header_bits

        if payload_length > available_bits // 8:
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
