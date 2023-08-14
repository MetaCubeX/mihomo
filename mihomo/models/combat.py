from pydantic import BaseModel


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


class TraceTreeNode(BaseModel):
    """
    Represents a node in the trace skill tree of a character.

    Attributes:
    - id (`int`): The ID of the trace.
    - level (`int`): The level of the trace.
    - max_level (`int`): The max level of the trace.
    - icon (`str`): The icon of the trace.
    - anchor (`str`): The position of the trace tree node.
    - parent (`int` | `None`): The preceding node id of trace.
    """

    id: int
    """The ID of the trace"""
    level: int
    """The level of the trace"""
    max_level: int
    """The max level of the trace"""
    icon: str
    """The icon of the trace"""
    anchor: str
    """The position of the trace tree node"""
    parent: int | None = None
    """The preceding node id of trace"""
