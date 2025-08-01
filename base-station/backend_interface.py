import uuid, json
import aiohttp
import asyncio
import traceback
from config import Config
from typing import Tuple, Optional


class BackendInterface:
    REQUEST_TIMEOUT = 15  # seconds
    def __init__(self, config: Config):
        self.station_id = config.get("station_id")
        self.backend_url = config.get("backend_url")
        self.station_key = config.get("station_key")
        self.session = None
        self.retry_delay = 2

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def send_received_packet(self, data: bytes, packet_id: uuid.UUID) -> bool:
        payload = {
            "station_id": self.station_id,
            "packet_id": str(packet_id),
            "data": list(data)
        }
        url = f"{self.backend_url}/rx"
        headers = {"Authorization": f"Bearer {self.station_key}"}
        try:
            assert self.session is not None, "Session not initialized"
            timeout = aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT)
            async with self.session.post(url, json=payload, headers=headers, timeout=timeout) as resp:
                response_body = await resp.text()
                print(f"[RX] POST /rx status: {resp.status} body: '{response_body}'")
                resp.raise_for_status()
                return True
        except RuntimeError as e:
            if repr(e).find("Session is closed") >= 0:
                # This is an acceptable error.
                print(f"send_received_packet got 'Session is closed', restarting")
                return False
        except aiohttp.ClientResponseError as e:
            print(f"send_received_packet got ClientResponseError, restarting")
            return False
        except Exception as e:
            traceback.print_exc()
            print(f"[RX] Send failed: {e}")
            raise

    async def get_next_tx_packet(self) -> Optional[Tuple[bytes, uuid.UUID]]:
        url = f"{self.backend_url}/tx"
        headers = {"Authorization": f"Bearer {self.station_key}"}
        try:
            assert self.session is not None, "Session not initialized"
            timeout = aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT)
            async with self.session.get(url, headers=headers, timeout=timeout) as resp:
                resp.raise_for_status()
                result = await resp.json()
                assert type(result) == list, "Expected a list of packets"
                ret = []
                for packet in result:
                    packet_id = uuid.UUID(packet["packet_id"])
                    packet_data = bytes(packet["data"])
                    ret.append((packet_data, packet_id))
                return ret
        except RuntimeError as e:
            if repr(e).find("Session is closed") >= 0:
                # This is an acceptable error.
                print(f"get_next_tx_packet got 'Session is closed', restarting")
                return []
        except aiohttp.ClientResponseError as e:
            print(f"get_next_tx_packet got ClientResponseError, restarting")
            return []
        except Exception as e:
            traceback.print_exc()
            print(f"[TX] Polling failed: {e}")
            raise

    async def get_station_score(self) -> Optional[int]:
        url = f"{self.backend_url}/station-score"
        headers = {"Authorization": f"Bearer {self.station_key}"}
        try:
            assert self.session is not None, "Session not initialized for getting station score"
            timeout = aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT)
            async with self.session.get(url, headers=headers, timeout=timeout) as resp:
                resp.raise_for_status()
                result = await resp.json()
                assert type(result) == int, "Expected a number"
                #print(f"Got score {result}")
                return result
        except RuntimeError as e:
            if repr(e).find("Session is closed") >= 0:
                # This is an acceptable error.
                print(f"get_station_score got 'Session is closed', restarting")
                return None
        except aiohttp.ClientResponseError as e:
            print(f"get_station_score got ClientResponseError, restarting")
            return None
        except Exception as e:
            traceback.print_exc()
            print(f"[TX] Polling station score failed: {e}")
            raise

