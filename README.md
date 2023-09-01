# outline-vpn-api-async

(A Python API wrapper for [Outline VPN](https://getoutline.org/).)

This is an async-copy of [outline-vpn-api](https://github.com/jadolg/outline-vpn-api/) by Jorge Alberto Díaz Orozco (Akiel) (diazorozcoj@gmail.com).

The author of the async-version is Alexander AXO (home@samopoznanie.ru).

## How to use

```python
from outline_vpn_async.outline_vpn import OutlineVPN

# Setup the access with the API URL (Use the one provided to you after the server setup)
client = OutlineVPN(api_url="https://127.0.0.1:51083/xlUG4F5BBft4rSrIvDSWuw", cert_sha256="4EFF7BB90BCE5D4A172D338DC91B5B9975E197E39E3FA4FC42353763C4E58765")
...
await client.close()

or:
async with OutlineVPN(api_url=server[2]) as client:  
    new_key = await client.create_key() # Create a new key

# Get all access URLs on the server
for key in await client.get_keys():
    print(key.access_url)

# Create a new key
new_key = await client.create_key()

# Rename it
await client.rename_key(new_key.key_id, "new_key")

# Delete it
await client.delete_key(new_key.key_id)

# Set a monthly data limit for a key (20MB)
await client.add_data_limit(new_key.key_id, 1000 * 1000 * 20)

# Remove the data limit
await client.delete_data_limit(new_key.key_id)

```
