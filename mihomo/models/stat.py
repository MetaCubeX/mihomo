from pydantic import BaseModel, Field


class Attribute(BaseModel):
    """
    Represents an attribute.

    Attributes:
        - field (`str`): The field of the attribute.
        - name (`str`): The name of the attribute.
        - icon (`str`): The attribute icon image.
        - value (`float`): The value of the attribute.
        - displayed_value (`str`): The displayed value of the attribute.
        - is_percent (`bool`): Indicates if the value is in percentage.
    """

    field: str
    """The field of the attribute"""
    name: str
    """The name of the attribute"""
    icon: str
    """The attribute icon image"""
    value: float
    """The value of the attribute"""
    displayed_value: str = Field(..., alias="display")
    """The displayed value of the attribute"""
    is_percent: bool = Field(..., alias="percent")
    """Indicates if the value is in percentage"""


class Property(BaseModel):
    """
    Represents a property.

    Attributes:
        - type (`str`): The type of the property.
        - field (`str`): The field of the property.
        - name (`str`): The name of the property.
        - icon (`str`): The property icon image.
        - value (`float`): The value of the property.
        - displayed_value (`str`): The displayed value of the property.
        - is_percent (`bool`): Indicates if the value is in percentage.
    """

    type: str
    """The type of the property"""
    field: str
    """The field of the property"""
    name: str
    """The name of the property"""
    icon: str
    """The property icon image"""
    value: float
    """The value of the property"""
    displayed_value: str = Field(..., alias="display")
    """The displayed value of the property"""
    is_percent: bool = Field(..., alias="percent")
    """Indicates if the value is in percentage"""


class MainAffix(Property):
    """
    Represents a relic main affix.

    Attributes:
        - type (`str`): The type of the affix.
        - field (`str`): The field of the affix.
        - name (`str`): The name of the affix.
        - icon (`str`): The affix icon image.
        - value (`float`): The value of the affix.
        - displayed_value (`str`): The displayed value of the affix.
        - is_percent (`bool`): Indicates if the value is in percentage.
    """

    ...


class SubAffix(MainAffix):
    """
    Represents a relic sub-affix.

    Attributes:
        - type (`str`): The type of the affix.
        - field (`str`): The field of the affix.
        - name (`str`): The name of the affix.
        - icon (`str`): The affix icon image.
        - value (`float`): The value of the affix.
        - displayed_value (`str`): The displayed value of the affix.
        - is_percent (`bool`): Indicates if the value is in percentage.
        - count (`int`): The upgrade times of the affix.
        - step (`int`): The additional value of the affix.
    """

    count: int
    """The upgrade times of the affix"""
    step: int
    """The additional value of the affix"""
