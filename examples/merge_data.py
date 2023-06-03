import asyncio

from mihomo import Language, MihomoAPI, tools


async def main():
    client = MihomoAPI(language=Language.EN)
    old_data = await client.fetch_user(800333171)

    # Change characters in game and wait for the API to refresh
    # ...

    new_data = await client.fetch_user(800333171)
    data = tools.merge_character_data(new_data, old_data)

    print(data)


asyncio.run(main())
