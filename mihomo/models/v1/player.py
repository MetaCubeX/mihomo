from pydantic import BaseModel, Field


class Player(BaseModel):
    """
    Player basic info

    Attributes:
        - uid (`str`): The player's uid.
        - name (`str`): The player's nickname.
        - level (`int`): The player's Trailblaze level.
        - icon (`str`): The player's profile picture.
        - signature (`str`): The player's bio.
    """

    uid: str
    """Player's uid"""
    name: str
    """Player's nickname"""
    level: int
    """Trailblaze level"""
    icon: str
    """Profile picture"""
    signature: str
    """Bio"""


class ForgottenHall(BaseModel):
    """The progress of the Forgotten Hall

    Attributes:
        - memory (`int`): The progress of the memory.
        - memory_of_chaos_id (`int` | `None`): The ID of the memory of chaos, or None if not applicable.
        - memory_of_chaos (`int` | `None`): The progress of the memory of chaos, or None if not applicable.
    """

    memory: int | None = Field(None, alias="PreMazeGroupIndex")
    """The progress of the memory"""
    memory_of_chaos_id: int | None = Field(None, alias="MazeGroupIndex")
    """The ID of the memory of chaos"""
    memory_of_chaos: int | None = Field(None, alias="MazeGroupID")
    """The progress of the memory of chaos"""


class PlayerSpaceInfo(BaseModel):
    """Player details

    Attributes:
        - forgotten_hall (`ForgottenHall` | None): The progress of the Forgotten Hall, or None if not applicable.
        - simulated_universes (`int`): The number of simulated universes passed.
        - light_cones (`int`): The number of light cones owned.
        - characters (`int`): The number of characters owned.
        - achievements (`int`): The number of achievements unlocked.
    """

    forgotten_hall: ForgottenHall | None = Field(None, alias="ChallengeData")
    """The progress of the Forgotten Hall"""
    simulated_universes: int = Field(0, alias="PassAreaProgress")
    """Number of simulated universes passed"""
    light_cones: int = Field(0, alias="LightConeCount")
    """Number of light cones owned"""
    characters: int = Field(0, alias="AvatarCount")
    """Number of characters owned"""
    achievements: int = Field(0, alias="AchievementCount")
    """Number of achievements unlocked"""
