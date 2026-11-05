"""LSB steganography encoder for Inkryptor."""

import struct
from pathlib import Path

from PIL import Image, UnidentifiedImageError


MAGIC = b"INKR"
HEADER_FORMAT = ">4sI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 8 bytes

MAX_PAYLOAD_SIZE = (1 << 32) - 1


class EmbeddingError(Exception):
    """Raised when payload embedding fails."""


def calculate_capacity(width: int, height: int) -> int:
    """Return maximum payload capacity in bytes, excluding the header."""

    total_bits = width * height * 3
    available_bits = max(0, total_bits - HEADER_SIZE * 8)

    return available_bits // 8


def _encode_bits(pixel_data: bytearray, payload: bytes) -> None:
    """Encode bytes into the least significant bits of RGB channels."""

    bit_index = 0

    for byte in payload:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1

            pixel_data[bit_index] = (
                (pixel_data[bit_index] & 0xFE) | bit
            )

            bit_index += 1


def embed_payload(
    payload: bytes,
    cover_path: str | Path,
    output_path: str | Path,
) -> None:
    """
    Embed a binary payload into an image using RGB LSB steganography.

    The output is always saved as PNG to preserve embedded bits.
    """

    if not isinstance(payload, bytes):
        raise EmbeddingError("Payload must be bytes.")

    if len(payload) > MAX_PAYLOAD_SIZE:
        raise EmbeddingError("Payload exceeds the supported size.")

    output_path = Path(output_path)

    if output_path.suffix.lower() != ".png":
        raise EmbeddingError("Output image must have a .png extension.")

    try:
        with Image.open(cover_path) as image:
            image.load()
            rgb_image = image.convert("RGB")

    except (OSError, UnidentifiedImageError) as exc:
        raise EmbeddingError("Unable to open the cover image.") from exc

    width, height = rgb_image.size

    capacity = calculate_capacity(width, height)

    if len(payload) > capacity:
        raise EmbeddingError(
            f"Payload too large. Maximum capacity: {capacity} bytes; "
            f"payload size: {len(payload)} bytes."
        )

    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        len(payload),
    )

    framed_payload = header + payload

    pixel_data = bytearray(rgb_image.tobytes())

    _encode_bits(pixel_data, framed_payload)

    encoded_image = Image.frombytes(
        "RGB",
        rgb_image.size,
        bytes(pixel_data),
    )

    try:
        encoded_image.save(output_path, format="PNG")
    except OSError as exc:
        raise EmbeddingError("Unable to save the output image.") from exc
    finally:
        encoded_image.close()
        rgb_image.close()
