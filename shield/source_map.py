"""Piecewise Python-character offsets. No source text or token values retained."""

from bisect import bisect_right
from dataclasses import dataclass, field


class SourceMapError(ValueError):
    def __init__(self):
        super().__init__("Source mapping failed.")


@dataclass(frozen=True, slots=True)
class SourcePiece:
    original_start: int
    original_end: int
    masked_start: int
    masked_end: int
    masked: bool


@dataclass(frozen=True, slots=True)
class SourceMap:
    original_length: int
    masked_length: int
    pieces: tuple[SourcePiece, ...]
    _starts: tuple[int, ...] = field(init=False, repr=False)

    def __post_init__(self):
        original = masked = 0
        previous_literal = False
        if (
            type(self.original_length) is not int
            or self.original_length < 0
            or type(self.masked_length) is not int
            or self.masked_length < 0
            or type(self.pieces) is not tuple
        ):
            raise SourceMapError()
        for piece in self.pieces:
            if (
                not isinstance(piece, SourcePiece)
                or any(
                    type(value) is not int
                    for value in (
                        piece.original_start,
                        piece.original_end,
                        piece.masked_start,
                        piece.masked_end,
                    )
                )
                or type(piece.masked) is not bool
            ):
                raise SourceMapError()
            if (
                piece.original_start != original
                or piece.masked_start != masked
                or piece.original_end <= original
                or piece.masked_end <= masked
            ):
                raise SourceMapError()
            if not piece.masked:
                if (
                    previous_literal
                    or piece.original_end - original != piece.masked_end - masked
                ):
                    raise SourceMapError()
            previous_literal = not piece.masked
            original, masked = piece.original_end, piece.masked_end
        if original != self.original_length or masked != self.masked_length:
            raise SourceMapError()
        object.__setattr__(self, "_starts", tuple(p.masked_start for p in self.pieces))

    def to_original(self, start: int, end: int) -> tuple[int, int] | None:
        if (
            type(start) is not int
            or type(end) is not int
            or start < 0
            or end <= start
            or end > self.masked_length
        ):
            raise SourceMapError()
        piece = self.pieces[bisect_right(self._starts, start) - 1]
        if piece.masked or end > piece.masked_end:
            return None
        offset = piece.original_start - piece.masked_start
        return start + offset, end + offset


def build_source_map(original_length: int, replacements) -> SourceMap:
    """Build from disjoint (original start, original end, placeholder length)."""
    try:
        if type(original_length) is not int or original_length < 0:
            raise SourceMapError()
        original = masked = 0
        pieces = []
        for start, end, size in sorted(replacements):
            if (
                any(type(v) is not int for v in (start, end, size))
                or start < original
                or end <= start
                or end > original_length
                or size <= 0
            ):
                raise SourceMapError()
            if start > original:
                stop = masked + start - original
                pieces.append(SourcePiece(original, start, masked, stop, False))
                masked = stop
            pieces.append(SourcePiece(start, end, masked, masked + size, True))
            original, masked = end, masked + size
        if original < original_length:
            pieces.append(
                SourcePiece(
                    original,
                    original_length,
                    masked,
                    masked + original_length - original,
                    False,
                )
            )
            masked += original_length - original
        return SourceMap(original_length, masked, tuple(pieces))
    except Exception:
        raise SourceMapError() from None
