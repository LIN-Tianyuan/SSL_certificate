import re
from _console import to_ascii

RE_VALID_DOMAIN_NAME = re.compile(
    r"(([\da-zA-Z])([_\w-]{,62})\.){,127}"
    r"(([\da-zA-Z])[_\w-]{,61})?"
    r"([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,})))$",
    re.IGNORECASE
)


def is_valid_domain(s: str) -> bool:
    return RE_VALID_DOMAIN_NAME.match(to_ascii(s.lower().strip())) is not None