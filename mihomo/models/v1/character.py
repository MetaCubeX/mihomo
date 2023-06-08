from typing import Any

from pydantic import BaseModel, Field, root_validator

from .equipment import LightCone, Relic, RelicSet


class EidolonIcon(BaseModel):
    """
    Represents an Eidolon icon.

    Attributes:
        - icon (`str`): The eidolon icon.
        - unlock (`bool`): Indicates if the eidolon is unlocked.
    """

    icon: str
    """The eidolon icon"""
    unlock: bool
    """Indicates if the eidolon is unlocked"""


class Trace(BaseModel):
    """
    Represents a character's skill trace.

    Attributes:
        - name (`str`): The name of the trace.
        - level (`int`): The level of the trace.
        - type (`str`): The type of the trace.
        - icon (`str`): The trace icon.
    """

    name: str
    """The name of the trace"""
    level: int
    """The level of the trace"""
    type: str
    """The type of the trace"""
    icon: str
    """The trace icon"""


class Stat(BaseModel):
    """
    Represents a character's stat.

    Attributes:
        - name (`str`): The name of the stat.
        - base (`str`): The base value of the stat.
        - addition (`str` | `None`): The additional value of the stat, or None if not applicable.
        - icon (`str`): The stat icon.
    """

    name: str
    """The name of the stat"""
    base: str
    """The base value of the stat"""
    addition: str | None = None
    """The additional value of the stat"""
    icon: str
    """The stat icon"""


class Character(BaseModel):
    """
    Represents a character.

    Attributes:
    - Basic info:
        - id (`str`): The character's ID.
        - name (`str`): The character's name.
        - rarity (`int`): The character's rarity.
        - level (`int`): The character's level.
    - Eidolon
        - eidolon (`int`): The character's eidolon rank.
        - eidolon_icons (list[`EidolonIcon`]): The list of eidolon icons.
    - Image
        - icon (`str`): The character avatar image
        - preview (`str`): The character's preview image.
        - portrait (`str`): The character's portrait image.
    - Combat type
        - path (`str`): The character's path.
        - path_icon (`str`): The character's path icon.
        - element (`str`): The character's element.
        - element_icon (`str`): The character's element icon.
        - color (`str`): The character's element color.
    - Equipment
        - traces (list[`Trace`]): The list of character's skill traces.
        - light_cone (`LightCone` | `None`): The character's light cone (weapon), or None if not applicable.
        - relics (list[`Relic`] | `None`): The list of character's relics, or None if not applicable.
        - relic_set (list[`RelicSet`] | `None`): The list of character's relic sets, or None if not applicable.
        - stats (list[`Stat`]): The list of character's stats.
    """

    id: str
    """Character's ID"""
    name: str
    """Character's name"""
    rarity: int
    """Character's rarity"""
    level: int
    """Character's level"""

    eidolon: int = Field(..., alias="rank")
    """Character's eidolon rank"""
    eidolon_icons: list[EidolonIcon] = Field(..., alias="rank_icons")
    """The list of eidolon icons"""

    preview: str
    """Character preview image"""
    portrait: str
    """Character portrait image"""

    path: str
    """Character's path"""
    path_icon: str
    """Character's path icon"""

    element: str
    """Character's element"""
    element_icon: str
    """Character's element icon"""

    color: str
    """Character's element color"""

    traces: list[Trace] = Field(..., alias="skill")
    """The list of character's skill traces"""
    light_cone: LightCone | None = None
    """Character's light cone (weapon)"""
    relics: list[Relic] | None = Field(None, alias="relic")
    """The list of character's relics"""
    relic_set: list[RelicSet] | None = None
    """The list of character's relic sets"""
    stats: list[Stat] = Field(..., alias="property")
    """The list of character's stats"""

    @root_validator(pre=True)
    def dict_to_list(cls, data: dict[str, Any]):
        # The keys of the original dict is not necessary, so remove them here.
        if isinstance(data, dict) and data.get("relic") is not None:
            if isinstance(data["relic"], dict):
                data["relic"] = list(data["relic"].values())
        return data

    @property
    def icon(self) -> str:
        """Character avatar image"""
        return f"icon/character/{self.id}.png"
