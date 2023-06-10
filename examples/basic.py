import asyncio

from mihomo import Language, MihomoAPI
from mihomo.models import StarrailInfoParsed
from mihomo.models.v1 import StarrailInfoParsedV1

client = MihomoAPI(language=Language.EN)


async def v1():
    data: StarrailInfoParsedV1 = await client.fetch_user_v1(800333171)

    print(f"Name: {data.player.name}")
    print(f"Level: {data.player.level}")
    print(f"Signature: {data.player.signature}")
    print(f"Achievements: {data.player_details.achievements}")
    print(f"Characters count: {data.player_details.characters}")
    print(f"Profile picture url: {client.get_icon_url(data.player.icon)}")
    for character in data.characters:
        print("-----------")
        print(f"Name: {character.name}")
        print(f"Rarity: {character.rarity}")
        print(f"Level: {character.level}")
        print(f"Avatar url: {client.get_icon_url(character.icon)}")
        print(f"Preview url: {client.get_icon_url(character.preview)}")
        print(f"Portrait url: {client.get_icon_url(character.portrait)}")


async def v2():
    data: StarrailInfoParsed = await client.fetch_user(800333171, replace_icon_name_with_url=True)

    print(f"Name: {data.player.name}")
    print(f"Level: {data.player.level}")
    print(f"Signature: {data.player.signature}")
    print(f"Profile picture url: {data.player.avatar.icon}")
    for character in data.characters:
        print("-----------")
        print(f"Name: {character.name}")
        print(f"Rarity: {character.rarity}")
        print(f"Portrait url: {character.portrait}")


asyncio.run(v1())
asyncio.run(v2())
