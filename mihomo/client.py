import typing
from enum import Enum

import aiohttp

from .errors import HttpRequestError
from .models import StarrailInfoParsed
from .tools import remove_empty_dict, replace_trailblazer_name


class Language(Enum):
    CHT = "cht"
    CHS = "chs"
    DE = "de"
    EN = "en"
    ES = "es"
    FR = "fr"
    ID = "id"
    JP = "jp"
    KR = "kr"
    PT = "pt"
    RU = "ru"
    TH = "th"
    VI = "vi"


class MihomoAPI:
    """
    Represents an client for Mihomo API.

    Args:
        language (Language, optional):
            The language to use for API responses.Defaults to Language.CHT.

    Attributes:
        - BASE_URL (str): The base URL of the API.
        - ASSET_URL (str): The base URL for the asset files.

    """

    BASE_URL: typing.Final[str] = "https://api.mihomo.me/sr_info_parsed"
    ASSET_URL: typing.Final[str] = "https://raw.githubusercontent.com/Mar-7th/StarRailRes/master"

    def __init__(self, language: Language = Language.CHT):
        self.lang = language

    async def request(
        self,
        uid: int | str,
        language: Language,
    ) -> typing.Any:
        """
        Makes an HTTP request to the API.

        Args:
            - uid (int | str): The user ID.
            - language (Language): The language to use for the API response.

        Returns:
            typing.Any: The response from the API.

        Raises:
            HttpRequestError: If the HTTP request fails.

        """
        url = self.BASE_URL + "/" + str(uid)
        params = {}
        if language != Language.CHS:
            params.update({"lang": language.value})
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json(encoding="utf-8")
                else:
                    raise HttpRequestError(response.status, str(response.reason))

    async def fetch_user(self, uid: int) -> StarrailInfoParsed:
        """
        Fetches user data from the API.

        Args:
            uid (int): The user ID.

        Returns:
            StarrailInfoParsed: The parsed user data from mihomo API.

        """
        data = await self.request(uid, self.lang)
        data = remove_empty_dict(data)
        data = StarrailInfoParsed.parse_obj(data)
        data = replace_trailblazer_name(data)
        return data

    def get_icon_url(self, icon: str) -> str:
        """
        Gets the asset url for the given icon.

        Args:
            icon (str): The icon name.

        Returns:
            str: The asset url for the icon.

        """
        return self.ASSET_URL + "/" + icon
