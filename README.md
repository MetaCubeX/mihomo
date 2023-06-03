# mihomo
A simple Python Pydantic model (type hint and autocompletion support) for Honkai: Star Rail parsed data from the Mihomo API.

API url: https://api.mihomo.me/sr_info_parsed/{UID}?lang={LANG}

## Installation
```
pip install -U git+https://github.com/KT-Yeh/mihomo.git
```

## Usage

### Basic 
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
        print(f"Rarity: {character.rarity}")
        print(f"Level: {character.level}")
        print(f"Avatar url: {client.get_icon_url(character.icon)}")
        print(f"Preview url: {client.get_icon_url(character.preview)}")
        print(f"Portrait url: {client.get_icon_url(character.portrait)}")

asyncio.run(main())
```

### Tools
`from mihomo import tools`
#### Remove Duplicate Character
```py
    data = await client.fetch_user(800333171)
    data = tools.remove_duplicate_character(data)
```

#### Merge Character Data
```py
    old_data = await client.fetch_user(800333171)

    # Change characters in game and wait for the API to refresh
    # ...

    new_data = await client.fetch_user(800333171)
    data = tools.merge_character_data(new_data, old_data)
```

### Data Persistence
Take pickle and json as an example
```py
import pickle
import zlib
from mihomo import MihomoAPI, Language, StarrailInfoParsed

client = MihomoAPI(language=Language.EN)
data = await client.fetch_user(800333171)

# Save
pickle_data = zlib.compress(pickle.dumps(data))
print(len(pickle_data))
json_data = data.json(by_alias=True, ensure_ascii=False)
print(len(json_data))

# Load
data_from_pickle = pickle.loads(zlib.decompress(pickle_data))
data_from_json = StarrailInfoParsed.parse_raw(json_data)
print(type(data_from_pickle))
print(type(data_from_json))
```
