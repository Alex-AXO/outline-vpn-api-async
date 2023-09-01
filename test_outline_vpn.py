"""
Integration tests for the API wrapper
"""

import json
import re
import pytest
from outline_vpn_async.outline_vpn import OutlineVPN


@pytest.fixture
def client_info():
    install_log = open("outline-install.log", "r").read()
    json_text = re.findall("({[^}]+})", install_log)[0]
    api_data = json.loads(json_text)
    return api_data.get("apiUrl"), api_data.get("certSha256")


@pytest.mark.asyncio
async def test_get_keys(client_info):
    api_url, cert_sha256 = client_info
    client = OutlineVPN(api_url, cert_sha256)
    keys = await client.get_keys()
    assert len(keys) >= 1
    await client.session.close()


@pytest.mark.asyncio
async def test_cud_key(client_info):
    api_url, cert_sha256 = client_info
    client = OutlineVPN(api_url, cert_sha256)

    new_key = await client.create_key()
    assert new_key is not None
    assert int(new_key.key_id) > 0

    named_key = await client.create_key(key_name="Test Key")
    assert named_key.name == "Test Key"

    assert await client.rename_key(new_key.key_id, "a_name")
    assert await client.delete_key(new_key.key_id)

    await client.session.close()


@pytest.mark.asyncio
async def test_limits(client_info):  # pylint: disable=W0621
    """Test setting, retrieving and removing custom limits"""
    new_limit = 1024 * 1024 * 20
    target_key_id = 0

    api_url, cert_sha256 = client_info
    client = OutlineVPN(api_url, cert_sha256)

    assert await client.add_data_limit(target_key_id, new_limit)

    keys = await client.get_keys()
    for key in keys:
        if key.key_id == target_key_id:
            assert key.data_limit == new_limit

    assert await client.delete_data_limit(target_key_id)


@pytest.mark.asyncio
async def test_server_methods(client_info):

    api_url, cert_sha256 = client_info
    client = OutlineVPN(api_url, cert_sha256)

    server_info = await client.get_server_information()
    assert server_info is not None

    new_server_name = "Test Server name"
    assert await client.set_server_name(new_server_name)

    new_hostname = "example.com"
    assert await client.set_hostname(new_hostname)

    new_port_for_access_keys = 11233
    assert await client.set_port_new_for_access_keys(new_port_for_access_keys)

    updated_server_info = await client.get_server_information()
    assert updated_server_info.get("name") == new_server_name
    assert updated_server_info.get("hostnameForAccessKeys") == new_hostname
    assert updated_server_info.get("portForNewAccessKeys") == new_port_for_access_keys

    assert await client.set_server_name(server_info.get("name"))
    assert await client.set_hostname(server_info.get("hostnameForAccessKeys"))
    assert await client.set_port_new_for_access_keys(server_info.get("portForNewAccessKeys"))


@pytest.mark.asyncio
async def test_metrics_status(client_info):

    api_url, cert_sha256 = client_info
    client = OutlineVPN(api_url, cert_sha256)

    metrics_status = await client.get_metrics_status()
    assert await client.set_metrics_status(not metrics_status)
    assert await client.get_metrics_status() != metrics_status
    await client.set_metrics_status(metrics_status)


@pytest.mark.asyncio
async def test_data_limit_for_all_keys(client_info):

    api_url, cert_sha256 = client_info
    client = OutlineVPN(api_url, cert_sha256)

    assert await client.set_data_limit_for_all_keys(1024 * 1024 * 20)
    assert await client.delete_data_limit_for_all_keys()


@pytest.mark.asyncio
async def test_get_transferred_data(client_info):
    """Call the method and assert it responds something"""

    api_url, cert_sha256 = client_info
    client = OutlineVPN(api_url, cert_sha256)

    data = await client.get_transferred_data()
    assert data is not None
    assert "bytesTransferredByUserId" in data
