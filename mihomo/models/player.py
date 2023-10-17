from pydantic import BaseModel, Field, root_validator


class Avatar(BaseModel):
    """Profile picture"""

    id: int
    name: str
    icon: str


class ForgottenHall(BaseModel):
    """The progress of the Forgotten Hall

    Attributes:
        - memory (`int`): The progress of the memory.
        - memory_of_chaos_id (`int`): The ID of the memory of chaos, or None if not applicable.
        - memory_of_chaos (`int`): The progress of the memory of chaos, or None if not applicable.
    """

    memory: int = Field(..., alias="level")
    """The progress of the memory (level)"""
    memory_of_chaos_id: int = Field(..., alias="chaos_id")
    """The ID of the memory of chaos (chaos_id)"""
    memory_of_chaos: int = Field(..., alias="chaos_level")
    """The progress of the memory of chaos (chaos_level)"""


class Player(BaseModel):
    """
    Player basic info

    Attributes:
        - uid (`int`): The player's uid.
        - name (`str`): The player's nickname.
        - level (`int`): The player's Trailblaze level.
        - world_level (`int`): The player's Equilibrium level.
        - friend_count (`int`): The number of friends.
        - avatar (`Avatar`): The player's profile picture.
        - signature (`str`): The player's bio.
        - is_display (`bool`): Is the player's profile display enabled.

        - forgotten_hall (`ForgottenHall` | None): The progress of the Forgotten Hall, or None if not applicable.
        - simulated_universes (`int`): The number of simulated universes passed.
        - light_cones (`int`): The number of light cones owned.
        - characters (`int`): The number of characters owned.
        - achievements (`int`): The number of achievements unlocked.
    """

    uid: int
    """Player's uid"""
    name: str = Field(..., alias="nickname")
    """Player's nickname"""
    level: int
    """Trailblaze level"""
    world_level: int
    """Equilibrium level"""
    friend_count: int
    """Number of friends"""
    avatar: Avatar
    """Profile picture"""
    signature: str
    """Bio"""
    is_display: bool
    """Is the player's profile display enabled."""

    forgotten_hall: ForgottenHall | None = Field(None, alias="memory_data")
    """The progress of the Forgotten Hall (memory_data)"""
    simulated_universes: int = Field(0, alias="universe_level")
    """Number of simulated universes passed (universe_level)"""
    light_cones: int = Field(0, alias="light_cone_count")
    """Number of light cones owned"""
    characters: int = Field(0, alias="avatar_count")
    """Number of characters owned"""
    achievements: int = Field(0, alias="achievement_count")
    """Number of achievements unlocked"""

    @root_validator(pre=True)
    def decompose_space_info(cls, data):
        if isinstance(data, dict):
            space_info = data.get("space_info")
            if isinstance(space_info, dict):
                data.update(space_info)
        return data

    @root_validator(pre=True)
    def transform_for_backward_compatibility(cls, data):
        if isinstance(data, dict):
            if "pass_area_progress" in data and "universe_level" not in data:
                data["universe_level"] = data["pass_area_progress"]
            if "challenge_data" in data and "memory_data" not in data:
                c: dict[str, int] = data["challenge_data"]
                data["memory_data"] = {}
                data["memory_data"]["level"] = c.get("pre_maze_group_index")
                data["memory_data"]["chaos_id"] = c.get("maze_group_id")
                data["memory_data"]["chaos_level"] = c.get("maze_group_index")
        return data
