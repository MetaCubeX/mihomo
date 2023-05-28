from pydantic import BaseModel, Field


class LightCone(BaseModel):
    """
    Represents a light cone (weapon).

    Attributes:
        - name (`str`): The name of the light cone.
        - rarity (`int`): The rarity of the light cone.
        - superimpose (`int`): The superimpose rank of the light cone.
        - level (`int`): The level of the light cone.
        - icon (`str`): The light cone icon.
    """

    name: str
    rarity: int
    superimpose: int = Field(..., alias="rank")
    level: int
    icon: str


class RelicProperty(BaseModel):
    """
    Represents a property of a relic.

    Attributes:
        - name (`str`): The name of the relic property.
        - value (`str`): The value of the relic property.
        - icon (`str`): The property icon.
    """

    name: str
    value: str
    icon: str


class Relic(BaseModel):
    """
    Represents a relic.

    Attributes:
        - name (`str`): The name of the relic.
        - rarity (`int`): The rarity of the relic.
        - level (`int`): The level of the relic.
        - main_property (`RelicProperty`): The main property of the relic.
        - sub_property (list[`RelicProperty`]): The list of sub properties of the relic.
        - icon (`str`): The relic icon.
    """

    name: str
    rarity: int
    level: int
    main_property: RelicProperty
    sub_property: list[RelicProperty]
    icon: str


class RelicSet(BaseModel):
    """
    Represents a set of relics.

    Attributes:
        - name (`str`): The name of the relic set.
        - icon (`str`): The relic set icon.
        - desc (`int`): The description of the relic set.
    """

    name: str
    icon: str
    desc: int
