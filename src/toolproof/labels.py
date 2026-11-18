"""Provenance labels and opaque labelled values.

Every value an agent handles carries a :class:`Label`:

* ``sources``: where the data came from (``"user"``, ``"tool:read_email"``,
  ``"web:example.com"`` ...).  Anything derived from several values carries the
  union of their sources.
* ``readers``: who may see it.  ``None`` means unrestricted.  Anything derived
  from several values may be read only by the intersection of their readers.

A :class:`Value` hides its data from accidental use: ``str()``, f-strings,
``format()``, ``%`` formatting and ``json.dumps`` all fail loudly instead of
silently dropping the label.  Data comes out only through ``.data`` (an explicit,
greppable act) or through the monitor.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, FrozenSet, Iterable, Optional

__all__ = ["Label", "Value", "TRUSTED_DEFAULT"]

TRUSTED_DEFAULT = ("user", "planner")


@dataclass(frozen=True)
class Label:
    sources: FrozenSet[str] = frozenset()
    readers: Optional[FrozenSet[str]] = None

    @staticmethod
    def make(sources: Iterable[str] = (), readers: Optional[Iterable[str]] = None) -> "Label":
        return Label(frozenset(sources), None if readers is None else frozenset(readers))

    def join(self, other: "Label") -> "Label":
        """Label of anything computed from data labelled ``self`` and ``other``."""
        if self.readers is None:
            readers = other.readers
        elif other.readers is None:
            readers = self.readers
        else:
            readers = self.readers & other.readers
        return Label(self.sources | other.sources, readers)

    @staticmethod
    def join_all(labels: Iterable["Label"]) -> "Label":
        out = Label()
        for lab in labels:
            out = out.join(lab)
        return out

    def to_dict(self) -> dict:
        return {
            "sources": sorted(self.sources),
            "readers": None if self.readers is None else sorted(self.readers),
        }

    @staticmethod
    def from_dict(d: dict) -> "Label":
        return Label.make(d.get("sources", ()), d.get("readers"))


class Value:
    """Data plus its :class:`Label`.  Equality is by identity so comparing two
    values cannot leak their contents."""

    __slots__ = ("_data", "label")

    def __init__(self, data: Any, label: Label):
        object.__setattr__(self, "_data", data)
        object.__setattr__(self, "label", label)

    def __setattr__(self, name, value):
        raise AttributeError("Value is immutable")

    @classmethod
    def const(cls, data: Any, sources: Iterable[str] = ("user",), readers=None) -> "Value":
        return cls(data, Label.make(sources, readers))

    @classmethod
    def derive(cls, fn: Callable[..., Any], *values: "Value") -> "Value":
        """Compute ``fn`` over the data of ``values``; the result carries the join of their labels."""
        label = Label.join_all(v.label for v in values)
        return cls(fn(*(v._data for v in values)), label)

    @property
    def data(self) -> Any:
        """Raw data.  Using this is a deliberate act: the label is not carried forward."""
        return self._data

    def _refuse(self, *_a, **_k):
        raise TypeError(
            "Value is opaque: converting it to str/bytes/json would drop its provenance label. "
            "Use Value.derive(...) to compute with it, or .data to take the raw data on purpose."
        )

    __str__ = __format__ = __bytes__ = __int__ = __float__ = _refuse
    __index__ = __iter__ = __len__ = _refuse

    def __repr__(self) -> str:
        src = ",".join(sorted(self.label.sources)) or "-"
        return f"Value(<opaque>, sources={{{src}}})"

    __hash__ = object.__hash__

    def __eq__(self, other) -> bool:
        return self is other
