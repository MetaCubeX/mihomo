from typing import TypeVar

from .models import Character, StarrailInfoParsed

T = TypeVar("T")


def remove_empty_dict(data: T) -> T:
    """
    Recursively removes empty dictionaries from the given raw data.

    Args:
        - data (`T`): The input data.

    Returns:
        - `T`: The data with empty dictionaries removed.
    """
    if isinstance(data, dict):
        for key in data.keys():
            data[key] = None if (data[key] == {}) else remove_empty_dict(data[key])
    elif isinstance(data, list):
        for i in range(len(data)):
            data[i] = remove_empty_dict(data[i])
    return data


def replace_trailblazer_name(data: StarrailInfoParsed) -> StarrailInfoParsed:
    """
    Replaces the trailblazer name with the player's name.

    Args:
        - data (`StarrailInfoParsed`): The input StarrailInfoParsed data.

    Returns:
        - `StarrailInfoParsed`: The updated StarrailInfoParsed data.
    """
    for i in range(len(data.characters)):
        if data.characters[i].name == r"{NICKNAME}":
            data.characters[i].name = data.player.name
    return data


def remove_duplicate_character(data: StarrailInfoParsed) -> StarrailInfoParsed:
    """
    Removes duplicate characters from the given StarrailInfoParsed data.

    Args:
        - data (`StarrailInfoParsed`): The input StarrailInfoParsed data.

    Returns:
        - `StarrailInfoParsed`: The updated StarrailInfoParsed data without duplicate characters.
    """
    new_characters: list[Character] = []
    characters_ids: set[str] = set()
    for character in data.characters:
        if character.id not in characters_ids:
            new_characters.append(character)
            characters_ids.add(character.id)
    data.characters = new_characters
    return data


def merge_character_data(
    new_data: StarrailInfoParsed, old_data: StarrailInfoParsed
) -> StarrailInfoParsed:
    """
    Append the old data characters to the list of new data characters.
    The player's info from the old data will be omitted/discarded.

    Args:
        - new_data (`StarrailInfoParsed`): The new data to be merged.
        - old_data (`StarrailInfoParsed`): The old data to merge into.

    Returns:
        - `StarrailInfoParsed`: The merged new data.
    """
    for character in old_data.characters:
        new_data.characters.append(character)
    new_data = remove_duplicate_character(new_data)
    return new_data
