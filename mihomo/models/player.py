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

    memory: int = Field(..., alias="pre_maze_group_index")
    """The progress of the memory (pre_maze_group_index)"""
    memory_of_chaos_id: int = Field(..., alias="maze_group_id")
    """The ID of the memory of chaos (maze_group_id)"""
    memory_of_chaos: int = Field(..., alias="maze_group_index")
    """The progress of the memory of chaos (maze_group_index)"""


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

    forgotten_hall: ForgottenHall | None = Field(None, alias="challenge_data")
    """The progress of the Forgotten Hall (challenge_data)"""
    simulated_universes: int = Field(0, alias="pass_area_progress")
    """Number of simulated universes passed (pass_area_progress)"""
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
