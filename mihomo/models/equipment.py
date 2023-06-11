from pydantic import BaseModel, Field

from .combat import Path
from .stat import Attribute, MainAffix, Property, SubAffix


class LightCone(BaseModel):
    """
    Represents a light cone (weapon).

    Attributes:
        - id (`int`): The ID of the light cone.
        - name (`str`): The name of the light cone.
        - rarity (`int`): The rarity of the light cone.
        - superimpose (`int`): The superimpose rank of the light cone.
        - level (`int`): The current level of the light cone.
        - max_level (`int`): The maximum light cone level according to the current ascension phase.
        - ascension (`int`): The ascension phase of the light cone.
        - icon (`str`): The light cone icon image.
        - preview (`str`): The light cone preview image.
        - portrait (`str`): The light cone portrait image.
        - path (`Path`): The path of the light cone.
        - attributes (list[`Attribute`]): The list of attributes of the light cone.
        - properties (list[`Property`]): The list of properties of the light cone.
    """

    id: int
    """The ID of the light cone"""
    name: str
    """The name of the light cone"""
    rarity: int
    """The rarity of the light cone"""
    superimpose: int = Field(..., alias="rank")
    """The superimpose rank of the light cone"""
    level: int
    """The level of the light cone"""
    ascension: int = Field(..., alias="promotion")
    """The ascension phase of the light cone"""
    icon: str
    """The light cone icon image"""
    preview: str
    """The light cone preview image"""
    portrait: str
    """The light cone portrait image"""
    path: Path
    """The path of the light cone"""
    attributes: list[Attribute]
    """The list of attributes of the light cone"""
    properties: list[Property]
    """The list of properties of the light cone"""

    @property
    def max_level(self) -> int:
        """The maximum light cone level according to the current ascension phase"""
        return 20 + 10 * self.ascension


class Relic(BaseModel):
    """
    Represents a relic.

    Attributes:
        - id (`int`): The ID of the relic.
        - name (`str`): The name of the relic.
        - set_id (`int`): The ID of the relic set.
        - set_name (`str`): The name of the relic set.
        - rarity (`int`): The rarity of the relic.
        - level (`int`): The level of the relic.
        - main_property (`MainAffix`): The main affix of the relic.
        - sub_property (list[`SubAffix`]): The list of sub-affixes of the relic.
        - icon (`str`): The relic icon.
    """

    id: int
    """The ID of the relic"""
    name: str
    """The name of the relic"""
    set_id: int
    """The ID of the relic set"""
    set_name: str
    """The name of the relic set"""
    rarity: int
    """The rarity of the relic"""
    level: int
    """The level of the relic"""
    main_affix: MainAffix
    """The main affix of the relic"""
    sub_affixes: list[SubAffix] = Field([], alias="sub_affix")
    """The list of sub-affixes of the relic"""
    icon: str
    """The relic icon"""


class RelicSet(BaseModel):
    """
    Represents a set of relics.

    Attributes:
        - id (`int`): The ID of the relic set.
        - name (`str`): The name of the relic set.
        - icon (`str`): The icon of the relic set.
        - num (`int`): The number of relics in the set.
        - desc (`str`): The description of the relic set.
        - properties (list[`Property`]): The list of properties of the relic set.
    """

    id: int
    """The ID of the relic set"""
    name: str
    """The name of the relic set"""
    icon: str
    """The icon of the relic set"""
    num: int
    """The number of relics in the set"""
    desc: str
    """The description of the relic set"""
    properties: list[Property]
    """The list of properties of the relic set"""
