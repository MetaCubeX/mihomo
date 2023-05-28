# mihomo
A simple Python Pydantic model (type hint and autocompletion support) for Honkai: Star Rail parsed data from the Mihomo API.

API url: https://api.mihomo.me/sr_info_parsed/{UID}?lang={LANG}

## Installation
```
pip install -U git+https://github.com/KT-Yeh/mihomo.git
```

## Usage
An example for https://api.mihomo.me/sr_info_parsed/800333171?lang=en

```py
import asyncio

from mihomo import MihomoAPI, Language

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
        print(f"rarity: {character.rarity}")
        print(f"Level: {character.level}")
        print(f"Avatar url: {client.get_icon_url(character.icon)}")
        print(f"Preview url: {client.get_icon_url(character.preview)}")
        print(f"portrait url: {client.get_icon_url(character.portrait)}")

asyncio.run(main())
```