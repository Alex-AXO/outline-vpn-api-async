""" From A.XO | async VPN Outline API | Python """

from typing import List, Optional, Dict, Any
from dataclasses import dataclass
import aiohttp
from aiohttp import TCPConnector, FormData, ClientTimeout
import asyncio
from urllib.parse import urlparse
import sys
from loguru import logger

# Настройка логирования
logger.remove()  # Удаляем стандартный обработчик
logger.add(
    sys.stdout,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
    level="INFO",
    colorize=True
)


@dataclass
class OutlineKey:
    """Описывает ключ Outline VPN"""
    key_id: str
    name: str
    password: str
    port: int
    method: str
    access_url: str
    used_bytes: int
    data_limit: Optional[int]


class OutlineServerError(Exception):
    """Базовый класс для ошибок Outline сервера"""
    pass


class OutlineVPN:
    """
    Асинхронная обёртка для Outline VPN API.

    Пример использования:
        async with OutlineVPN(api_url=server_api) as client:
            keys = await client.get_keys()
            info = await client.get_server_information()
    """

    def __init__(self, api_url: str, *, timeout: int = 30):
        # Валидация URL
        try:
            parsed = urlparse(api_url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError("Invalid API URL format")
            self.api_url = api_url.rstrip('/')
        except Exception as e:
            logger.error(f"Invalid API URL provided: {api_url}")
            raise ValueError(f"Invalid API URL: {e}")

        logger.debug(f"Initializing OutlineVPN client for {self.api_url}")

        self.connector = TCPConnector(
            ssl=False,
            enable_cleanup_closed=True,
            keepalive_timeout=30,
            force_close=False
        )

        self.timeout = ClientTimeout(
            total=timeout,
            connect=timeout,
            sock_connect=timeout,
            sock_read=timeout
        )

        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Инициализация сессии при входе в контекстный менеджер"""
        if not self._session:
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=self.connector
            )
            logger.debug("Created new aiohttp session")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Закрытие сессии при выходе из контекстного менеджера"""
        if self._session:
            logger.debug("Closing aiohttp session")
            await self._session.close()
            self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        """Получение активной сессии"""
        if not self._session:
            raise RuntimeError("Session not initialized. Use 'async with' context manager.")
        return self._session

    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Any:
        """Выполнение HTTP-запроса с обработкой ошибок"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        try:
            logger.debug(f"Making {method} request to {url}")
            async with self.session.request(method, url, **kwargs) as response:
                if response.status == 204:
                    return True

                if response.status >= 400:
                    error_text = await response.text()
                    logger.error(f"Request failed: {response.status} - {error_text}")
                    raise OutlineServerError(f"Request failed with status {response.status}: {error_text}")

                return await response.json() if response.content_length else None

        except aiohttp.ClientError as e:
            logger.error(f"Network error in request to {url}: {e}")
            raise OutlineServerError(f"Network error: {e}")
        except asyncio.TimeoutError:
            logger.error(f"Timeout in request to {url}")
            raise OutlineServerError("Request timeout")
        except Exception as e:
            logger.error(f"Unexpected error in request to {url}: {e}")
            raise OutlineServerError(f"Unexpected error: {e}")

    async def get_keys(self) -> List[OutlineKey]:
        """Получить все ключи Outline VPN"""
        logger.debug("Fetching all VPN keys")
        try:
            # Параллельный запрос ключей и метрик
            tasks = [
                self._make_request('GET', 'access-keys/'),
                self._make_request('GET', 'metrics/transfer')
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Проверяем результаты на ошибки
            for result in results:
                if isinstance(result, Exception):
                    raise result

            data, metrics = results

            if "accessKeys" not in data:
                raise OutlineServerError("Response does not contain 'accessKeys'")

            if "bytesTransferredByUserId" not in metrics:
                raise OutlineServerError("Response does not contain 'bytesTransferredByUserId'")

            result = []
            for key in data["accessKeys"]:
                key_id = key.get("id")
                result.append(
                    OutlineKey(
                        key_id=key_id,
                        name=key.get("name"),
                        password=key.get("password"),
                        port=key.get("port"),
                        method=key.get("method"),
                        access_url=key.get("accessUrl"),
                        data_limit=key.get("dataLimit", {}).get("bytes"),
                        used_bytes=metrics["bytesTransferredByUserId"].get(key_id, 0),
                    )
                )

            logger.info(f"Successfully fetched {len(result)} keys")
            return result

        except Exception as e:
            logger.error(f"Failed to get keys: {e}")
            raise OutlineServerError(f"Failed to get keys: {e}")

    async def get_key(self, key_id: str) -> OutlineKey:
        """Получить информацию об одном ключе"""
        logger.debug(f"Fetching key information for ID: {key_id}")
        try:
            tasks = [
                self._make_request('GET', f'access-keys/{key_id}'),
                self._make_request('GET', 'metrics/transfer')
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Проверяем результаты на ошибки
            for result in results:
                if isinstance(result, Exception):
                    raise result

            key, metrics = results

            outline_key = OutlineKey(
                key_id=key.get("id"),
                name=key.get("name"),
                password=key.get("password"),
                port=key.get("port"),
                method=key.get("method"),
                access_url=key.get("accessUrl"),
                data_limit=key.get("dataLimit", {}).get("bytes"),
                used_bytes=metrics["bytesTransferredByUserId"].get(key.get("id"), 0),
            )

            logger.debug(f"Successfully fetched key {key_id}")
            return outline_key

        except Exception as e:
            logger.error(f"Failed to get key {key_id}: {e}")
            raise OutlineServerError(f"Failed to get key: {e}")

    async def create_key(self, key_name: Optional[str] = None) -> OutlineKey:
        """Создать новый ключ"""
        logger.debug(f"Creating new key{' with name: ' + key_name if key_name else ''}")
        try:
            key = await self._make_request('POST', 'access-keys/')

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
                renamed = await self.rename_key(outline_key.key_id, key_name)
                if renamed:
                    outline_key.name = key_name

            logger.info(f"Successfully created key {outline_key.key_id}")
            return outline_key

        except Exception as e:
            logger.error(f"Failed to create key: {e}")
            raise OutlineServerError(f"Failed to create key: {e}")

    async def rename_key(self, key_id: str, name: str) -> bool:
        """Переименовать ключ"""
        logger.debug(f"Renaming key {key_id} to {name}")
        form = FormData()
        form.add_field("name", name)
        try:
            result = await self._make_request(
                'PUT',
                f'access-keys/{key_id}/name',
                data=form
            )
            if result:
                logger.info(f"Successfully renamed key {key_id}")
            return result
        except Exception as e:
            logger.error(f"Failed to rename key {key_id}: {e}")
            raise OutlineServerError(f"Failed to rename key: {e}")

    async def delete_key(self, key_id: str) -> bool:
        """Удалить ключ"""
        logger.debug(f"Deleting key {key_id}")
        try:
            result = await self._make_request('DELETE', f'access-keys/{key_id}')
            if result:
                logger.info(f"Successfully deleted key {key_id}")
            return result
        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {e}")
            raise OutlineServerError(f"Failed to delete key: {e}")

    async def add_data_limit(self, key_id: str, limit_bytes: int) -> bool:
        """Установить ограничение трафика (в байтах) для ключа"""
        logger.debug(f"Setting data limit for key {key_id}: {limit_bytes} bytes")
        try:
            result = await self._make_request(
                'PUT',
                f'access-keys/{key_id}/data-limit',
                json={"limit": {"bytes": limit_bytes}}
            )
            if result:
                logger.info(f"Set data limit {limit_bytes} bytes for key {key_id}")
            return result
        except Exception as e:
            logger.error(f"Failed to set data limit for key {key_id}: {e}")
            raise OutlineServerError(f"Failed to set data limit: {e}")

    async def delete_data_limit(self, key_id: str) -> bool:
        """Удалить ограничение трафика для ключа"""
        logger.debug(f"Removing data limit for key {key_id}")
        try:
            result = await self._make_request('DELETE', f'access-keys/{key_id}/data-limit')
            if result:
                logger.info(f"Removed data limit for key {key_id}")
            return result
        except Exception as e:
            logger.error(f"Failed to remove data limit for key {key_id}: {e}")
            raise OutlineServerError(f"Failed to remove data limit: {e}")

    async def get_transferred_data(self) -> dict:
        """
        Получить информацию о переданном трафике для всех ключей.
        Возвращаемый формат:
            {"bytesTransferredByUserId": { "1": 1008040941, ... }}
        """
        logger.debug("Fetching transferred data metrics")
        try:
            data = await self._make_request('GET', 'metrics/transfer')
            logger.debug("Successfully fetched transfer metrics")
            return data
        except Exception as e:
            logger.error(f"Failed to get transfer metrics: {e}")
            raise OutlineServerError(f"Failed to get transfer metrics: {e}")

    async def get_server_information(self) -> Dict[str, Any]:
        """Получить информацию о сервере"""
        logger.debug("Fetching server information")
        try:
            data = await self._make_request('GET', 'server')
            logger.debug("Successfully fetched server information")
            return data
        except Exception as e:
            logger.error(f"Failed to get server information: {e}")
            raise OutlineServerError(f"Failed to get server information: {e}")

    async def set_server_name(self, name: str) -> bool:
        """Переименовать сервер"""
        logger.debug(f"Setting server name to: {name}")
        try:
            result = await self._make_request('PUT', 'name', json={"name": name})
            if result:
                logger.info(f"Successfully renamed server to {name}")
            return result
        except Exception as e:
            logger.error(f"Failed to rename server: {e}")
            raise OutlineServerError(f"Failed to rename server: {e}")

    async def set_hostname(self, hostname: str) -> bool:
        """Изменить hostname для доступа к ключам"""
        logger.debug(f"Setting hostname to: {hostname}")
        try:
            result = await self._make_request(
                'PUT',
                'server/hostname-for-access-keys',
                json={"hostname": hostname}
            )
            if result:
                logger.info(f"Successfully set hostname to {hostname}")
            return result
        except Exception as e:
            logger.error(f"Failed to set hostname: {e}")
            raise OutlineServerError(f"Failed to set hostname: {e}")

    async def get_metrics_status(self) -> bool:
        """Получить статус передачи метрик (включены или нет)"""
        logger.debug("Checking metrics status")
        try:
            data = await self._make_request('GET', 'metrics/enabled')
            status = data.get("metricsEnabled", False)
            logger.debug(f"Metrics status: {'enabled' if status else 'disabled'}")
            return status
        except Exception as e:
            logger.error(f"Failed to get metrics status: {e}")
            raise OutlineServerError(f"Failed to get metrics status: {e}")

    async def set_metrics_status(self, status: bool) -> bool:
        """Включить или отключить передачу метрик"""
        logger.debug(f"Setting metrics status to: {'enabled' if status else 'disabled'}")
        try:
            result = await self._make_request(
                'PUT',
                'metrics/enabled',
                json={"metricsEnabled": status}
            )
            if result:
                logger.info(f"Successfully {'enabled' if status else 'disabled'} metrics")
            return result
        except Exception as e:
            logger.error(f"Failed to set metrics status: {e}")
            raise OutlineServerError(f"Failed to set metrics status: {e}")

    async def set_port_new_for_access_keys(self, port: int) -> bool:
        """
        Изменить порт для новых ключей.
        При статусе 400 или 409 выбрасывается исключение.
        """
        logger.debug(f"Setting new port for access keys: {port}")
        try:
            result = await self._make_request(
                'PUT',
                'server/port-for-new-access-keys',
                json={"port": port}
            )
            if result:
                logger.info(f"Successfully set new port to {port}")
            return result
        except Exception as e:
            if isinstance(e, OutlineServerError):
                if "400" in str(e):
                    raise OutlineServerError("Port must be an integer from 1 through 65535")
                elif "409" in str(e):
                    raise OutlineServerError("Port is already in use by another service")
            logger.error(f"Failed to set new port: {e}")
            raise OutlineServerError(f"Failed to set new port: {e}")

    async def set_data_limit_for_all_keys(self, limit_bytes: int) -> bool:
        """Установить ограничение трафика для всех ключей"""
        logger.debug(f"Setting data limit for all keys: {limit_bytes} bytes")
        try:
            result = await self._make_request(
                'PUT',
                'server/access-key-data-limit',
                json={"limit": {"bytes": limit_bytes}}
            )
            if result:
                logger.info(f"Set data limit {limit_bytes} bytes for all keys")
            return result
        except Exception as e:
            logger.error(f"Failed to set data limit for all keys: {e}")
            raise OutlineServerError(f"Failed to set data limit for all keys: {e}")

    async def delete_data_limit_for_all_keys(self) -> bool:
        """Снять ограничение трафика для всех ключей"""
        logger.debug("Removing data limit for all keys")
        try:
            result = await self._make_request('DELETE', 'server/access-key-data-limit')
            if result:
                logger.info("Successfully removed data limit for all keys")
            return result
        except Exception as e:
            logger.error(f"Failed to remove data limit for all keys: {e}")
            raise OutlineServerError(f"Failed to remove data limit for all keys: {e}")

    async def close(self):
        """Закрыть сессию вручную"""
        if self._session:
            logger.debug("Manually closing session")
            await self._session.close()
            self._session = None
