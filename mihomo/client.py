import typing
from enum import Enum

import aiohttp

from . import tools
from .errors import HttpRequestError, InvalidParams, UserNotFound
from .models import StarrailInfoParsed
from .models.v1 import StarrailInfoParsedV1


class Language(Enum):
    CHT = "cht"
    CHS = "cn"
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
    ASSET_URL: typing.Final[
        str
    ] = "https://raw.githubusercontent.com/Mar-7th/StarRailRes/master"

    def __init__(self, language: Language = Language.CHT):
        self.lang = language

    async def request(
        self,
        uid: int | str,
        language: Language,
        *,
        params: dict[str, str] = {},
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
            InvalidParams: If the API request contains invalid parameters.
            UserNotFound: If the requested user is not found.

        """
        url = self.BASE_URL + "/" + str(uid)
        params.update({"lang": language.value})

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                match response.status:
                    case 200:
                        return await response.json(encoding="utf-8")
                    case 400:
                        try:
                            data = await response.json(encoding="utf-8")
                        except:
                            raise InvalidParams()
                        else:
                            if isinstance(data, dict) and (
                                detail := data.get("detail")
                            ):
                                raise InvalidParams(detail)
                            raise InvalidParams()
                    case 404:
                        raise UserNotFound()
                    case _:
                        raise HttpRequestError(response.status, str(response.reason))

    async def fetch_user(
        self,
        uid: int,
        *,
        replace_icon_name_with_url: bool = False,
    ) -> StarrailInfoParsed:
        """
        Fetches user data from the API.

        Args:
            - uid (`int`): The user ID.
            - replace_icon_name_with_url (`bool`): Whether to replace icon names with asset URLs.

        Returns:
            StarrailInfoParsed: The parsed user data from mihomo API.

        """
        data = await self.request(uid, self.lang)
        if replace_icon_name_with_url is True:
            data = tools.replace_icon_name_with_url(data)
        data = StarrailInfoParsed.parse_obj(data)
        return data

    async def fetch_user_v1(
        self,
        uid: int,
        *,
        replace_icon_name_with_url: bool = False,
    ) -> StarrailInfoParsedV1:
        """
        Fetches user data from the API using version 1 format.

        Args:
            - uid (`int`): The user ID.
            - replace_icon_name_with_url (`bool`): Whether to replace icon names with asset URLs.

        Returns:
            StarrailInfoParsedV1: The parsed user data from the Mihomo API (version 1).

        """
        data = await self.request(uid, self.lang, params={"version": "v1"})
        data = tools.remove_empty_dict(data)
        if replace_icon_name_with_url is True:
            data = tools.replace_icon_name_with_url(data)
        data = StarrailInfoParsedV1.parse_obj(data)
        data = tools.replace_trailblazer_name(data)
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
