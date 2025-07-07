# mcauth

Authenticate with **Microsoft**, **Xbox Live**, and **Minecraft (Java + Bedrock)** using the device code flow. This is useful for headless clients, bots, or any tool that needs to log into Minecraft without a browser. This tool was written by the Mcbehub team for the website Mcbehub.de.

## Features

- Microsoft OAuth2 Device Code flow
- Xbox Live + XSTS authentication
- Minecraft Java + Bedrock authentication
- Token caching
- EC key management (generates and stores PEM key)
- Async interface using `httpx`

---

## Requirements

Python 3.8+

Install dependencies:

```bash
pip install -r requirements.txt
````

---

## Usage

### Basic Example

```python
import asyncio
from auth import MinecraftAuth

async def main():
    async with MinecraftAuth(cache_path="auth_cache.json") as auth:
        await auth.authenticate_with_microsoft()
        await auth.authenticate_with_xbox()
        await auth.authenticate_minecraft_java()
        await auth.authenticate_minecraft_bedrock()

asyncio.run(main())
```

---

## Auth Flow

### 1. Microsoft Login

* Uses device code flow.
* Prompts user to visit login page and enter a code.
* Returns OAuth token.

### 2. Xbox Authentication

* Authenticates with Xbox Live using Microsoft token.
* Requests XSTS token.

### 3. Minecraft Java

* Uses Xbox XSTS token to get Minecraft Java token via `api.minecraftservices.com`.

### 4. Minecraft Bedrock

* Authenticates using Xbox XSTS + EC JWT signature.
* Communicates with `multiplayer.minecraft.net`.

---

## Token Caching

All tokens are cached in JSON (`cache_path`) to avoid re-authentication. Tokens are automatically refreshed when expired.

---

## Key Management

The client uses an EC private key (`ec_private.pem`) for Bedrock authentication.

* If the file exists, it is loaded.
* If not, a new key is generated and saved.

---

## File Structure

```
project/
├── auth.py              # Main authentication client
├── constants.py         # Endpoint and error mappings
├── requirements.txt     # Dependencies
ec_private.pem           # Auto-generated EC key (optional)
auth_cache.json          # Auto-generated token cache (optional)
main.py                  # Main file
```

---

## Logging

Logs are sent via the `mcauth` logger. Configure it as needed:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## Error Handling

Common Xbox error codes are mapped in `constants.py`. Example:

```python
XBOX_ERRORS = {
    2148916234: 'Xbox terms not accepted',
    2148916236: 'Age verification needed',
    ...
}
```

---

## License

MIT

---

## Credits

[PrismarineJS](https://github.com/PrismarineJS/prismarine-auth)

---

## Disclaimer

This is **not** an official Microsoft or Mojang tool. Use at your own risk. For educational or development purposes only.
