from __future__ import annotations
from typing import Any, ClassVar, Iterable, Iterator, Self, Unpack

from pydantic import BaseModel, ConfigDict

from ..util import MISSING, typename
from ..util.collections import merge


__all__ = ("Model",)


class Model(BaseModel, frozen=True):
    model_sort_keys: ClassVar[tuple[type[Model], tuple[str, ...]]]

    def __init_subclass__(
        cls,
        sort_keys: Iterable[str] = (),
        **kwargs: Unpack[ConfigDict],
    ) -> None:
        if keys := tuple(sort_keys):
            cls.model_sort_keys = (cls, keys)
        return super().__init_subclass__(**kwargs)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self!s})"

    def __str__(self) -> str:
        return " ".join(
            f"{k}={v!r}"
            for k, v in self.model_fields_set_dict.items()
            if not (f := type(self).model_fields.get(k)) or (not f.exclude and f.repr)
        )

    def __gt__(self, that: Self) -> bool:
        if (sort_cls := self.model_sort_keys[0]) != that.model_sort_keys[0]:
            return NotImplemented
        if not self.model_sort_keys[1]:
            raise NotImplementedError(
                f"{typename(sort_cls)} objects are not sortable, no sort keys defined"
            )
        for s, o in zip(self.model_sort_keys_iter, that.model_sort_keys_iter):
            if s[1] > o[1]:
                return True
            elif s[1] < o[1]:
                break
        return False

    @property
    def model_sort_keys_iter(self) -> Iterator[tuple[str, Any]]:
        for key in self.model_sort_keys[1]:
            value = getattr(self, key, None)
            yield key, MISSING if value is None else value

    @property
    def model_fields_set_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.model_fields_set}

    def model_replace(self, **fields) -> Self:
        return self.model_validate({**self.model_fields_set_dict, **fields})

    def model_merge(self, other: Model | dict) -> Self:
        if isinstance(other, Model):
            other = {k: getattr(other, k) for k in other.model_fields_set}
        return self.model_validate(merge(self.model_fields_set_dict, other))


Model.model_sort_keys = (Model, ())
