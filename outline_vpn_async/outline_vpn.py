"""
API wrapper for Outline VPN
"""

import typing
from dataclasses import dataclass
import aiohttp
from aiohttp import TCPConnector, ClientSession

import requests
from urllib3 import PoolManager


@dataclass
class OutlineKey:
    """
    Describes a key in the Outline server
    """

    key_id: int
    name: str
    password: str
    port: int
    method: str
    access_url: str
    used_bytes: int
    data_limit: typing.Optional[int]


class OutlineServerErrorException(Exception):
    pass


class _FingerprintAdapter(requests.adapters.HTTPAdapter):
    """
    This adapter injected into the requests session will check that the
    fingerprint for the certificate matches for every request
    """
    def __init__(self, fingerprint=None, **kwargs):
        self.fingerprint = str(fingerprint)
        super(_FingerprintAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            assert_fingerprint=self.fingerprint,
        )


class OutlineVPN:
    """
    An Outline VPN connection
    """

    def __init__(self, api_url: str, cert_sha256: str = None):
        self.api_url = api_url
        self.connector = TCPConnector(ssl=False)  # Отключение SSL verification
        self.session = aiohttp.ClientSession(connector=self.connector)

    async def get_keys(self):
        """Get all keys in the outline server asynchronously"""
        async with self.session.get(f"{self.api_url}/access-keys/") as response:
            if response.status == 200:
                response_json = await response.json()
                if "accessKeys" in response_json:
                    async with self.session.get(f"{self.api_url}/metrics/transfer") as response_metrics:
                        if response_metrics.status >= 400:
                            raise OutlineServerErrorException("Unable to get metrics")

                        response_metrics_json = await response_metrics.json()
                        if "bytesTransferredByUserId" not in response_metrics_json:
                            raise OutlineServerErrorException("Unable to get metrics")

                        result = []
                        for key in response_json.get("accessKeys"):
                            result.append(
                                OutlineKey(
                                    key_id=key.get("id"),
                                    name=key.get("name"),
                                    password=key.get("password"),
                                    port=key.get("port"),
                                    method=key.get("method"),
                                    access_url=key.get("accessUrl"),
                                    data_limit=key.get("dataLimit", {}).get("bytes"),
                                    used_bytes=response_metrics_json
                                    .get("bytesTransferredByUserId")
                                    .get(key.get("id")),
                                )
                            )
                        return result
            raise OutlineServerErrorException("Unable to retrieve keys")

    async def create_key(self, key_name=None):
        """Create a new key"""
        async with self.session.post(f"{self.api_url}/access-keys/") as response:
            if response.status == 201:
                key = await response.json()
                outline_key = OutlineKey(
                    key_id=key.get("id"),
                    name=key.get("name"),
                    password=key.get("password"),
                    port=key.get("port"),
                    method=key.get("method"),
                    access_url=key.get("accessUrl"),
                    used_bytes=0,
                    data_limit=None,
                )
                if key_name:
                    # renamed = await self.rename_key(outline_key.key_id, key_name, session)
                    renamed = await self.rename_key(outline_key.key_id, key_name)
                    if renamed:
                        outline_key.name = key_name
                return outline_key

            raise OutlineServerErrorException("Unable to create key")

    async def delete_key(self, key_id: int) -> bool:
        """Delete a key"""
        async with self.session.delete(f"{self.api_url}/access-keys/{key_id}") as response:
            return response.status == 204

    async def rename_key(self, key_id: int, name: str) -> bool:
        """Rename a key"""
        payload = {"name": name}
        async with self.session.put(f"{self.api_url}/access-keys/{key_id}/name", json=payload) as response:
            return response.status == 204

    async def add_data_limit(self, key_id: int, limit_bytes: int) -> bool:
        """Set data limit for a key (in bytes)"""
        data = {"limit": {"bytes": limit_bytes}}
        async with self.session.put(
                f"{self.api_url}/access-keys/{key_id}/data-limit", json=data
        ) as response:
            return response.status == 204

    async def delete_data_limit(self, key_id: int) -> bool:
        """Removes data limit for a key"""
        async with self.session.delete(
                f"{self.api_url}/access-keys/{key_id}/data-limit"
        ) as response:
            return response.status == 204

    async def get_transferred_data(self):
        """Gets how much data all keys have used"""
        async with self.session.get(f"{self.api_url}/metrics/transfer") as response:
            if response.status >= 400:
                raise OutlineServerErrorException("Unable to get metrics")

            response_json = await response.json()
            if "bytesTransferredByUserId" not in response_json:
                raise OutlineServerErrorException("Unable to get metrics")

            return response_json

    async def get_server_information(self):
        """Get information about the server"""
        async with self.session.get(f"{self.api_url}/server") as response:
            if response.status != 200:
                raise OutlineServerErrorException("Unable to get information about the server")

            return await response.json()

    async def set_server_name(self, name: str) -> bool:
        """Renames the server"""
        async with self.session.put(f"{self.api_url}/name", json={"name": name}) as response:
            return response.status == 204

    async def set_hostname(self, hostname: str) -> bool:
        """Changes the hostname for access keys.
        Must be a valid hostname or IP address."""
        async with self.session.put(
                f"{self.api_url}/server/hostname-for-access-keys", json={"hostname": hostname}
        ) as response:
            return response.status == 204

    async def get_metrics_status(self) -> bool:
        """Returns whether metrics is being shared"""
        async with self.session.get(f"{self.api_url}/metrics/enabled") as response:
            data = await response.json()
            return data.get("metricsEnabled")

    async def set_metrics_status(self, status: bool) -> bool:
        """Enables or disables sharing of metrics"""
        async with self.session.put(
                f"{self.api_url}/metrics/enabled", json={"metricsEnabled": status}
        ) as response:
            return response.status == 204

    async def set_port_new_for_access_keys(self, port: int) -> bool:
        """Changes the default port for newly created access keys.
        This can be a port already used for access keys."""
        async with self.session.put(
                f"{self.api_url}/server/port-for-new-access-keys", json={"port": port}
        ) as response:
            if response.status == 400:
                raise OutlineServerErrorException(
                    "The requested port wasn't an integer from 1 through 65535, or the request had no port parameter."
                )
            elif response.status == 409:
                raise OutlineServerErrorException(
                    "The requested port was already in use by another service."
                )
            return response.status == 204

    async def set_data_limit_for_all_keys(self, limit_bytes: int) -> bool:
        """Sets a data transfer limit for all access keys."""
        async with self.session.put(
                f"{self.api_url}/server/access-key-data-limit", json={"limit": {"bytes": limit_bytes}}
        ) as response:
            return response.status == 204

    async def delete_data_limit_for_all_keys(self) -> bool:
        """Removes the access key data limit, lifting data transfer restrictions on all access keys."""
        async with self.session.delete(f"{self.api_url}/server/access-key-data-limit") as response:
            return response.status == 204

    async def close(self):
        await self.session.close()

    # async def __aenter__(self):
    #     return self
    #
    # async def __aexit__(self, exc_type, exc, tb):
    #     await self.session.close()
