from typing import Any

from pydantic import BaseModel, Field, root_validator

from .combat import Attribute, Element, Path, Property
from .equipment import LightCone, Relic, RelicSet


class Trace(BaseModel):
    """
    Represents a character's skill trace.

    Attributes:
        - id (`int`): The ID of the trace.
        - name (`str`): The name of the trace.
        - level (`int`): The current level of the trace.
        - max_level (`int`): The maximum level of the trace.
        - element (`Element` | None): The element of the trace, or None if not applicable.
        - type (`str`): The type of the trace.
        - type_text (`str`): The type text of the trace.
        - effect (`str`): The effect of the trace.
        - effect_text (`str`): The effect text of the trace.
        - simple_desc (`str`): The simple description of the trace.
        - desc (`str`): The detailed description of the trace.
        - icon (`str`): The trace icon.
    """

    id: int
    """The ID of the trace"""
    name: str
    """The name of the trace"""
    level: int
    """The current level of the trace"""
    max_level: int
    """The maximum level of the trace"""
    element: Element | None = None
    """The element of the trace"""
    type: str
    """The type of the trace"""
    type_text: str
    """The type text of the trace"""
    effect: str
    """The effect of the trace"""
    effect_text: str
    """The effect text of the trace"""
    simple_desc: str
    """The simple description of the trace"""
    desc: str
    """The detailed description of the trace"""
    icon: str
    """The trace icon"""


class Character(BaseModel):
    """
    Represents a character.

    Attributes:
    - Basic info:
        - id (`str`): The character's ID.
        - name (`str`): The character's name.
        - rarity (`int`): The character's rarity.
        - level (`int`): The character's current level.
        - max_level (`int`): The maximum character level according to the current ascension phase.
        - ascension (`int`): Ascension phase.
        - eidolon (`int`): The character's eidolon rank.
    - Image
        - icon (`str`): The character avatar image
        - preview (`str`): The character's preview image.
        - portrait (`str`): The character's portrait image.
    - Combat
        - path (`Path`): The character's path.
        - element (`Element`): The character's element.
    - Equipment
        - traces (list[`Trace`]): The list of character's skill traces.
        - light_cone (`LightCone` | `None`): The character's light cone (weapon), or None if not applicable.
        - relics (list[`Relic`] | `None`): The list of character's relics, or None if not applicable.
        - relic_set (list[`RelicSet`] | `None`): The list of character's relic sets, or None if not applicable.
        - stats (list[`Stat`]): The list of character's stats.
    - Stats
        - attributes (list[`Attribute`]): The list of character's attributes.
        - additions (list[`Attribute`]): The list of character's additional attributes.
        - properties (list[`Property`]): The list of character's properties.
    """

    id: str
    """Character's ID"""
    name: str
    """Character's name"""
    rarity: int
    """Character's rarity"""
    level: int
    """Character's level"""
    ascension: int = Field(..., alias="promotion")
    """Ascension phase"""
    eidolon: int = Field(..., alias="rank")
    """Character's eidolon rank"""

    icon: str
    """Character avatar image"""
    preview: str
    """Character preview image"""
    portrait: str
    """Character portrait image"""

    path: Path
    """Character's path"""
    element: Element
    """Character's element"""

    traces: list[Trace] = Field(..., alias="skills")
    """The list of character's skill traces"""
    light_cone: LightCone | None = None
    """Character's light cone (weapon)"""
    relics: list[Relic] = []
    """The list of character's relics"""
    relic_sets: list[RelicSet] = []
    """The list of character's relic sets"""

    attributes: list[Attribute]
    """The list of character's attributes"""
    additions: list[Attribute]
    """The list of character's additional attributes"""
    properties: list[Property]
    """The list of character's properties"""

    @property
    def max_level(self) -> int:
        """The maximum character level according to the current ascension phase"""
        return 20 + 10 * self.ascension
