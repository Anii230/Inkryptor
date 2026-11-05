import struct

import pytest

from PIL import Image

from inkryptor.embed import (
    embed_payload,
    calculate_capacity,
    EmbeddingError,
    MAGIC,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAX_IMAGE_PIXELS,
)

from inkryptor.extract import (
    extract_payload,
    ExtractionError,
)


@pytest.fixture
def cover_image(tmp_path):
    path = tmp_path / "cover.png"

    image = Image.new("RGB", (100, 100), color=(120, 160, 200))
    image.save(path)
    image.close()

    return path


# --------------------------------------------------
# Basic embedding and extraction
# --------------------------------------------------

def test_embed_extract_roundtrip(cover_image, tmp_path):
    payload = b"Hello from Inkryptor!"
    output = tmp_path / "stego.png"

    embed_payload(payload, cover_image, output)

    assert extract_payload(output) == payload


def test_large_payload_roundtrip(cover_image, tmp_path):
    payload = b"A" * 1000
    output = tmp_path / "large_stego.png"

    embed_payload(payload, cover_image, output)

    assert extract_payload(output) == payload


def test_empty_payload_roundtrip(cover_image, tmp_path):
    output = tmp_path / "empty_stego.png"

    embed_payload(b"", cover_image, output)

    assert extract_payload(output) == b""


def test_capacity_calculation():
    assert calculate_capacity(100, 100) == 3742


def test_payload_exceeding_capacity_fails(cover_image, tmp_path):
    capacity = calculate_capacity(100, 100)
    payload = b"A" * (capacity + 1)

    with pytest.raises(EmbeddingError):
        embed_payload(
            payload,
            cover_image,
            tmp_path / "overflow.png",
        )


def test_non_bytes_payload_fails(cover_image, tmp_path):
    with pytest.raises(EmbeddingError):
        embed_payload(
            "not bytes",
            cover_image,
            tmp_path / "invalid.png",
        )


def test_non_png_output_fails(cover_image, tmp_path):
    with pytest.raises(EmbeddingError):
        embed_payload(
            b"test",
            cover_image,
            tmp_path / "output.jpg",
        )


def test_image_without_payload_fails(cover_image):
    with pytest.raises(ExtractionError):
        extract_payload(cover_image)


def test_invalid_image_fails(tmp_path):
    invalid_image = tmp_path / "invalid.png"
    invalid_image.write_bytes(b"not an image")

    with pytest.raises(ExtractionError):
        extract_payload(invalid_image)


def test_source_image_remains_unchanged(cover_image, tmp_path):
    with Image.open(cover_image) as image:
        original = image.tobytes()

    output = tmp_path / "stego.png"

    embed_payload(b"test payload", cover_image, output)

    with Image.open(cover_image) as image:
        assert image.tobytes() == original


def test_rgba_cover_image(tmp_path):
    cover = tmp_path / "transparent.png"
    output = tmp_path / "stego.png"

    image = Image.new(
        "RGBA",
        (100, 100),
        color=(120, 160, 200, 128),
    )
    image.save(cover)
    image.close()

    payload = b"RGBA image test"

    embed_payload(payload, cover, output)

    assert extract_payload(output) == payload


# --------------------------------------------------
# Image validation
# --------------------------------------------------

def test_missing_cover_image_fails(tmp_path):
    with pytest.raises(EmbeddingError):
        embed_payload(
            b"test",
            tmp_path / "missing.png",
            tmp_path / "output.png",
        )


def test_invalid_dimensions_rejected():
    assert calculate_capacity(0, 100) == 0
    assert calculate_capacity(100, 0) == 0
    assert calculate_capacity(-10, 100) == 0


def test_oversized_cover_image_rejected(tmp_path):
    cover = tmp_path / "oversized.png"

    image = Image.new(
        "RGB",
        (MAX_IMAGE_PIXELS + 1, 1),
    )

    try:
        image.save(cover)
    finally:
        image.close()

    with pytest.raises(EmbeddingError):
        embed_payload(
            b"test",
            cover,
            tmp_path / "output.png",
        )


def test_oversized_image_extraction_rejected(tmp_path):
    cover = tmp_path / "oversized.png"

    image = Image.new(
        "RGB",
        (MAX_IMAGE_PIXELS + 1, 1),
    )

    try:
        image.save(cover)
    finally:
        image.close()

    with pytest.raises(ExtractionError):
        extract_payload(cover)


# --------------------------------------------------
# Output validation
# --------------------------------------------------

def test_existing_output_file_is_not_overwritten(
    cover_image,
    tmp_path,
):
    output = tmp_path / "existing.png"
    original_content = b"Do not overwrite this file."

    output.write_bytes(original_content)

    with pytest.raises(EmbeddingError):
        embed_payload(b"test", cover_image, output)

    assert output.read_bytes() == original_content


def test_input_and_output_paths_must_be_different(cover_image):
    original_content = cover_image.read_bytes()

    with pytest.raises(EmbeddingError):
        embed_payload(
            b"test",
            cover_image,
            cover_image,
        )

    assert cover_image.read_bytes() == original_content


def test_output_directory_must_exist(cover_image, tmp_path):
    output = tmp_path / "missing" / "output.png"

    with pytest.raises(EmbeddingError):
        embed_payload(b"test", cover_image, output)


# --------------------------------------------------
# Payload header validation
# --------------------------------------------------

def test_corrupted_magic_header_fails(cover_image, tmp_path):
    output = tmp_path / "corrupted_magic.png"

    embed_payload(b"test payload", cover_image, output)

    with Image.open(output) as image:
        pixel_data = bytearray(image.convert("RGB").tobytes())
        image_size = image.size

    # Replace the first four header bytes with invalid magic.
    invalid_header = struct.pack(
        HEADER_FORMAT,
        b"FAIL",
        len(b"test payload"),
    )

    for byte_index, byte in enumerate(invalid_header):
        for bit_offset in range(8):
            bit = (byte >> (7 - bit_offset)) & 1
            channel_index = byte_index * 8 + bit_offset

            pixel_data[channel_index] = (
                (pixel_data[channel_index] & 0xFE) | bit
            )

    corrupted = Image.frombytes(
        "RGB",
        image_size,
        bytes(pixel_data),
    )

    try:
        corrupted.save(output)
    finally:
        corrupted.close()

    with pytest.raises(ExtractionError):
        extract_payload(output)


def test_payload_length_exceeding_capacity_fails(
    cover_image,
    tmp_path,
):
    output = tmp_path / "invalid_length.png"

    embed_payload(b"test", cover_image, output)

    with Image.open(output) as image:
        pixel_data = bytearray(image.convert("RGB").tobytes())
        image_size = image.size

    available_capacity = calculate_capacity(*image_size)

    invalid_header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        available_capacity + 1,
    )

    for byte_index, byte in enumerate(invalid_header):
        for bit_offset in range(8):
            bit = (byte >> (7 - bit_offset)) & 1
            channel_index = byte_index * 8 + bit_offset

            pixel_data[channel_index] = (
                (pixel_data[channel_index] & 0xFE) | bit
            )

    corrupted = Image.frombytes(
        "RGB",
        image_size,
        bytes(pixel_data),
    )

    try:
        corrupted.save(output)
    finally:
        corrupted.close()

    with pytest.raises(ExtractionError):
        extract_payload(output)


def test_truncated_payload_fails(tmp_path):
    image_path = tmp_path / "truncated.png"

    image = Image.new("RGB", (10, 10), color=(120, 160, 200))

    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        1000,
    )

    pixel_data = bytearray(image.tobytes())

    for byte_index, byte in enumerate(header):
        for bit_offset in range(8):
            bit = (byte >> (7 - bit_offset)) & 1
            channel_index = byte_index * 8 + bit_offset

            pixel_data[channel_index] = (
                (pixel_data[channel_index] & 0xFE) | bit
            )

    corrupted = Image.frombytes(
        "RGB",
        image.size,
        bytes(pixel_data),
    )

    try:
        corrupted.save(image_path)
    finally:
        corrupted.close()
        image.close()

    with pytest.raises(ExtractionError):
        extract_payload(image_path)


def test_decode_bytes_rejects_out_of_bounds():
    from inkryptor.extract import _decode_bytes

    with pytest.raises(ExtractionError):
        _decode_bytes(
            b"\x00" * 8,
            start_bit=0,
            byte_count=2,
        )


def test_header_size_is_eight_bytes():
    assert HEADER_SIZE == 8
