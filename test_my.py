from outline_vpn_async.outline_vpn import OutlineVPN
import asyncio

import json
import re

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings

disable_warnings(InsecureRequestWarning)


async def main():

    install_log = open("outline-install.log", "r").read()
    json_text = re.findall("({[^}]+})", install_log)[0]
    api_data = json.loads(json_text)
    # return api_data.get("apiUrl"), api_data.get("certSha256")

    vpn = OutlineVPN(api_data.get("apiUrl"))

    # # Установка лимита данных
    # result = await vpn.add_data_limit(2, 12000000)  # 12 MB
    # if result:
    #     print("Data limit set successfully")

    keys = await vpn.get_keys()

    for i, key in enumerate(keys, 1):
        print(f"Key #{i}:")
        print(f"\tKey ID: {key.key_id}")
        print(f"\tName: {key.name}")
        print(f"\tPassword: {key.password}")
        print(f"\tPort: {key.port}")
        print(f"\tMethod: {key.method}")
        print(f"\tAccess URL: {key.access_url}")
        print(f"\tUsed Bytes: {key.used_bytes}")
        print(f"\tData Limit: {key.data_limit}")
        print('-' * 50)

    # # Create a new key
    # new_key = await vpn.create_key()
    #
    # # Rename it
    # await vpn.rename_key(new_key.key_id, "new_key_AXO_2 !")

    # # Delete it
    # await vpn.delete_key(25)

    # # Удаление лимита данных
    # result = await vpn.delete_data_limit(2)
    # if result:
    #     print("Data limit removed successfully")

    # # Изменение имени сервера
    # success = await vpn.set_server_name("axo-2-RU | ae")
    # if success:
    #     print("Server name updated successfully.")
    # else:
    #     print("Failed to update the server name.")

    # # Изменение хостнейма для ключей доступа
    # success = await vpn.set_hostname("new-hostname.com")
    # if success:
    #     print("Hostname updated successfully.")
    # else:
    #     print("Failed to update the hostname.")

    # Получение статуса метрик
    metrics_enabled = await vpn.get_metrics_status()
    print(f"Metrics Enabled: {metrics_enabled}")

    # # Установка статуса метрик
    # success = await vpn.set_metrics_status(True)
    # if success:
    #     print("Metrics status updated successfully.")
    # else:
    #     print("Failed to update the metrics status.")

    # # Установка порта для новых ключей доступа
    # success = await vpn.set_port_new_for_access_keys(1234)
    # if success:
    #     print("Port for new access keys updated successfully.")
    # else:
    #     print("Failed to update the port for new access keys.")

    # # Установка ограничения на передачу данных для всех ключей
    # success = await vpn.set_data_limit_for_all_keys(24000000000)  # 24 GB
    # if success:
    #     print("Data limit for all keys set successfully.")
    # else:
    #     print("Failed to set the data limit for all keys.")

    # # Удаление ограничения на передачу данных для всех ключей
    # success = await vpn.delete_data_limit_for_all_keys()
    # if success:
    #     print("Data limit for all keys deleted successfully.")
    # else:
    #     print("Failed to delete the data limit for all keys.")

    # Получение данных о трафике сервера
    transferred_data = await vpn.get_transferred_data()
    print(f"Transferred Data: {transferred_data}")

    # Получение информации о сервере
    server_info = await vpn.get_server_information()
    print(f"Server Information: {server_info}")

    await vpn.close()


if __name__ == "__main__":
    asyncio.run(main())
