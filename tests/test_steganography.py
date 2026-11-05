import pytest

from PIL import Image

from inkryptor.embed import (
    embed_payload,
    calculate_capacity,
    EmbeddingError,
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


def test_embed_extract_roundtrip(cover_image, tmp_path):
    payload = b"Hello from Inkryptor!"

    output = tmp_path / "stego.png"

    embed_payload(payload, cover_image, output)

    extracted = extract_payload(output)

    assert extracted == payload


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
    capacity = calculate_capacity(100, 100)

    assert capacity == 3742


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
    original = Image.open(cover_image).tobytes()

    output = tmp_path / "stego.png"

    embed_payload(b"test payload", cover_image, output)

    with Image.open(cover_image) as image:
        assert image.tobytes() == original


def test_rgba_cover_image( tmp_path):
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
