import cchardet as chardet
from unicodedata import normalize
import stransi


def remove_espaces(string: str) -> str:
    """Remove all ANSI escapes from the given string"""
    return "".join(
        map(
            str,
            filter(
                lambda _: not isinstance(_, stransi.E)
            )
        )
    )


def to_ascii(value: bytes | str) -> str:
    """Normalize the given string(bytes) to pure ascii"""
    if isinstance(value, bytes):
        # Try to decode as good as possible the given bytes
        text = value.decode(chardet.detect(value).get("encoding") or "utf-8")
    else:
        text = value
    return (
        # Normalize to ascii the text without ANSI escapes
        normalize("NFKD", remove_espaces(text))
        .encode("ascii", "ignore")
        .decode("ascii")
        .strip()
    )