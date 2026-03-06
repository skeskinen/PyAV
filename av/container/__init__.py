from fractions import Fraction
from typing import TypedDict

from .core import Container, Flags, open
from .input import InputContainer as InputContainer
from .output import OutputContainer as OutputContainer


class Chapter(TypedDict):
    """Chapter metadata dict used by Container.chapters() and set_chapters()."""

    id: int
    start: int
    end: int
    time_base: Fraction | None
    metadata: dict[str, str]
