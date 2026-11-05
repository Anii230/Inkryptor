"""LSB steganography encoder for Inkryptor."""

import struct
import warnings
from pathlib import Path

from PIL import Image, UnidentifiedImageError


MAGIC = b"INKR"
HEADER_FORMAT = ">4sI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

MAX_PAYLOAD_SIZE = (1 << 32) - 1
MAX_IMAGE_PIXELS = 40_000_000


class EmbeddingError(Exception):
    """Raised when payload embedding fails."""


def calculate_capacity(width: int, height: int) -> int:
    """Return maximum payload capacity in bytes, excluding the header."""

    if width <= 0 or height <= 0:
        return 0

    total_bits = width * height * 3
    available_bits = max(0, total_bits - HEADER_SIZE * 8)

    return available_bits // 8


def _validate_image_dimensions(width: int, height: int) -> None:
    """Reject images that exceed the configured pixel limit."""

    if width <= 0 or height <= 0:
        raise EmbeddingError("Invalid image dimensions.")

    if width * height > MAX_IMAGE_PIXELS:
        raise EmbeddingError(
            f"Image exceeds the maximum supported size "
            f"of {MAX_IMAGE_PIXELS:,} pixels."
        )


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

    cover_path = Path(cover_path).expanduser()
    output_path = Path(output_path).expanduser()

    if output_path.suffix.lower() != ".png":
        raise EmbeddingError("Output image must have a .png extension.")

    if not cover_path.is_file():
        raise EmbeddingError("Cover image does not exist.")

    if output_path.resolve() == cover_path.resolve():
        raise EmbeddingError("Input and output images must be different.")

    if output_path.exists():
        raise EmbeddingError("Output image already exists.")

    if not output_path.parent.is_dir():
        raise EmbeddingError("Output directory does not exist.")

    rgb_image = None

    try:
        with warnings.catch_warnings():
            warnings.simplefilter(
                "error",
                Image.DecompressionBombWarning,
            )

            with Image.open(cover_path) as image:
                width, height = image.size
                _validate_image_dimensions(width, height)

                image.load()
                rgb_image = image.convert("RGB")

    except (
        OSError,
        ValueError,
        UnidentifiedImageError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise EmbeddingError(
            "Unable to open or process the cover image."
        ) from exc

    try:
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
            if output_path.exists():
                raise EmbeddingError("Output image already exists.")

            encoded_image.save(output_path, format="PNG")

        except EmbeddingError:
            raise

        except OSError as exc:
            output_path.unlink(missing_ok=True)

            raise EmbeddingError(
                "Unable to save the output image."
            ) from exc

        finally:
            encoded_image.close()

    finally:
        if rgb_image is not None:
            rgb_image.close()
