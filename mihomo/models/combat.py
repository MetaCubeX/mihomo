from pydantic import BaseModel, Field


class Element(BaseModel):
    """
    Represents an element.

    Attributes:
        - id (`str`): The ID of the element.
        - name (`str`): The name of the element.
        - color (`str`): The color of the element.
        - icon (`str`): The element icon.
    """

    id: str
    """The ID of the element"""
    name: str
    """The name of the element"""
    color: str
    """The color of the element"""
    icon: str
    """The element icon"""


class Path(BaseModel):
    """
    Paths are congregations of Imaginary energy, with which the ideals harmonize.

    Attributes:
        - id (`str`): The ID of the path.
        - name (`str`): The name of the path.
        - icon (`str`): The path icon.
    """

    id: str
    """The ID of the path"""
    name: str
    """The name of the path"""
    icon: str
    """The path icon"""


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
