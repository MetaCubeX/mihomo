import asyncio

from mihomo import Language, MihomoAPI

client = MihomoAPI(language=Language.EN)


async def main():
    data = await client.fetch_user(800333171)

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


asyncio.run(main())
