from typing import TypeVar

from .models import StarrailInfoParsed

T = TypeVar("T")


def remove_empty_dict(data: T) -> T:
    if isinstance(data, dict):
        for key in data.keys():
            data[key] = None if (data[key] == {}) else remove_empty_dict(data[key])
    elif isinstance(data, list):
        for i in range(len(data)):
            data[i] = remove_empty_dict(data[i])
    return data


def replace_trailblazer_name(data: StarrailInfoParsed) -> StarrailInfoParsed:
    for i in range(len(data.characters)):
        if data.characters[i].name == r"{NICKNAME}":
            data.characters[i].name = data.player.name
    return data
