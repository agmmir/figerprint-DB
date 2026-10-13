import asyncio
import logging
import random
import re
from typing import List, Dict, Any, Optional
from urllib.parse import quote
import aiohttp
import yaml
import os
try:
    from .models import CameraInfo
    from .fingerprinter import fingerprint_camera, extra_favicon_paths
    from .probes.http import check_http_endpoint
except ImportError:
    from models import CameraInfo
    from fingerprinter import fingerprint_camera, extra_favicon_paths
    from probes.http import check_http_endpoint

logger = logging.getLogger(__name__)

class CameraScanner:
    """
    Asynchronous IP camera scanner.
    """

    def __init__(self, timeout: int = 10, semaphore_size: int = 50,
                 user: str = "", password: str = "", url_test_concurrency: int = 10,
                 port: Optional[int] = None, extra_ports: Optional[List[int]] = None):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(semaphore_size)
        # Default credentials used when scan() is called without explicit ones
        self.user = user
        self.password = password
        # Max concurrent URL checks for a single target IP
        self.url_test_concurrency = url_test_concurrency
        # Candidate TCP ports for IP cameras. A port is reported open solely when
        # _check_ports() confirms a TCP connection; no brand is attributed from a
        # port here (37777/37778 only feed the guarded Dahua fallback in scan()).
        self.common_ports = [
            # Web admin (HTTP/HTTPS alternates)
            80, 81, 82, 83, 84, 85, 88, 443, 8443,
            # RTSP
            554, 8554, 10554,
            # Hikvision
            8000, 8001, 8081, 9000, 9010,
            # Dahua (37777 TCP/DHIP; 37778 is the SDK port, also probed over TCP)
            37777, 37778, 50000,
            # Xiongmai / generic DVR (shared DVRIP port, not brand evidence)
            34567,
            # Common alternates
            8080, 8088, 8090, 5000,
            # Legacy services
            21, 22, 23,
        ]
        # Deduplicate, keep order
        seen = set()
        self.common_ports = [p for p in self.common_ports if not (p in seen or seen.add(p))]
        # Explicit "ip:port" target: scan/probe exactly this one TCP port and no other.
        self.explicit_port = port
        if port is not None:
            self.common_ports = [port]
        # User-requested additional TCP ports: port-checked only (HTTP/RTSP probes
        # keep their own targets), appended after the defaults, deduplicated.
        for extra in extra_ports or []:
            if extra not in self.common_ports:
                self.common_ports.append(extra)
        # Set per scan(): True when outbound TCP is intercepted (VPN/transparent
        # proxy), which makes every TCP connect "succeed" and open_ports unreliable.
        self._is_proxied = False
        # Load URL patterns from YAML
        self.url_patterns = self._load_url_patterns()
        # Non-standard favicon/image paths that signatures want hashed
        self._extra_favicon_paths = extra_favicon_paths()

    def _load_url_patterns(self) -> Dict[str, Any]:
        """Load URL patterns from all YAML files in the db/ directory."""
        patterns = {}
        db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db')
        if not os.path.isdir(db_dir):
            logger.warning(f"DB directory not found: {db_dir}")
            return patterns
        for filename in os.listdir(db_dir):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                filepath = os.path.join(db_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = yaml.safe_load(f)
                    if data:
                        # Merge data into patterns
                        for brand, brand_data in data.items():
                            if brand not in patterns:
                                patterns[brand] = {}
                            if isinstance(brand_data, dict):
                                patterns[brand].update(brand_data)
                            else:
                                # If brand_data is not a dict, just assign (unlikely)
                                patterns[brand] = brand_data
                    logger.debug(f"Loaded patterns from {filename}")
                except Exception as e:
                    logger.warning(f"Failed to load {filename}: {e}")
        if not patterns:
            logger.warning("No URL patterns loaded from db/ directory")
        else:
            # Log summary
            brand_count = len(patterns)
            model_count = sum(
                len([k for k in v.keys() if isinstance(k, str) and k not in ('snapshot', 'stream', 'overlay', 'ptz', 'other', '_generic')])
                for v in patterns.values() if isinstance(v, dict)
            )
            logger.debug(f"Loaded URL patterns: {brand_count} brands, {model_count} models")
        return patterns

    async def scan(self, ip: str, user: str = None, password: str = None) -> CameraInfo:
        """
        Scan a single IP address for IP cameras.

        Args:
            ip: The IP address to scan.
            user: Optional username; falls back to the instance default.
            password: Optional password; falls back to the instance default.

        Returns:
            CameraInfo object with scan results.
        """
        # Resolve credentials: explicit args override instance defaults
        user = self.user if user is None else user
        password = self.password if password is None else password

        logger.info(f"Scanning IP: {ip}")
        result = CameraInfo(ip=ip)

        # Is outbound TCP proxied? If so, TCP-connect results are meaningless.
        self._is_proxied = await self._is_tcp_proxied()
        result.tcp_proxied = self._is_proxied

        # Step 1: Quick port check
        open_ports = await self._check_ports(ip)
        result.open_ports = open_ports

        if not open_ports:
            logger.info(f"No open ports found on {ip}")
            return result

        if self._is_proxied:
            # open_ports is kept for information only; nothing is attributed from it
            # (no port-derived protocols, no port-37777 fallback below).
            result.evidence.append("port_scan: unreliable (tcp proxy detected)")
        else:
            # Determine likely protocols based on open ports
            result.protocols = self._determine_protocols(open_ports)

        # Step 2: HTTP probe
        http_info = await self._http_probe(ip)
        # Update result with information from HTTP probe
        if http_info:
            # Update manufacturer/model if found
            if http_info.get('manufacturer'):
                result.manufacturer = http_info['manufacturer']
            if http_info.get('model'):
                result.model = http_info['model']
            if http_info.get('firmware_version'):
                result.firmware_version = http_info['firmware_version']

        # Step 3: ONVIF WS-Discovery (for local networks)
        # We'll implement this later if needed

        # Step 4: RTSP probe
        rtsp_info = await self._rtsp_probe(ip)
        if rtsp_info:
            # Update manufacturer/model if found and not already set
            if not result.manufacturer and rtsp_info.get('manufacturer'):
                result.manufacturer = rtsp_info['manufacturer']
            if not result.model and rtsp_info.get('model'):
                result.model = rtsp_info['model']

        # Step 5: Fingerprinting to refine manufacturer/model
        # We'll use the collected information to fingerprint
        fingerprint_data = await self._gather_fingerprint_data(ip, open_ports, http_info, rtsp_info)
        if fingerprint_data:
            result.network_status = fingerprint_data.get('_network_status', 'unknown')
            # Internal "_"-prefixed keys (probe statuses) are not fingerprint fields
            fp_input = {k: v for k, v in fingerprint_data.items() if not k.startswith('_')}
            fp_result = fingerprint_camera(fp_input)
            if fp_result:
                if not result.manufacturer:
                    result.manufacturer = fp_result.get('manufacturer')
                if not result.model:
                    result.model = fp_result.get('model')
                if not result.firmware_version:
                    result.firmware_version = fp_result.get('firmware_version')
                if not result.serial_number and fp_result.get('serial_number'):
                    result.serial_number = fp_result['serial_number']
                # Propagate detection confidence (max() semantics) and evidence trail
                if fp_result.get('confidence') is not None:
                    result.confidence = max(result.confidence, fp_result['confidence'])
                for _ev in fp_result.get('evidence', []):
                    if _ev not in result.evidence:
                        result.evidence.append(_ev)

        # Step 5b: Authenticated device info (Hikvision ISAPI) when credentials are present
        # Explicit ip:port targets skip 5b/5c: these probes use fixed default ports.
        if self.explicit_port is None and user and password and result.manufacturer \
                and result.manufacturer.lower() == 'hikvision':
            try:
                from .probes.isapi import isapi_device_info
            except ImportError:
                from probes.isapi import isapi_device_info
            dev_info = await isapi_device_info(ip, user, password, self.timeout)
            if dev_info:
                if dev_info.get('model'):
                    result.model = dev_info['model']
                if dev_info.get('firmware_version'):
                    result.firmware_version = dev_info['firmware_version']
                if dev_info.get('serial_number'):
                    result.serial_number = dev_info['serial_number']

        # Step 5c: Authenticated firmware retrieval (Dahua magicBox CGI) when
        # credentials are present, the device is Dahua, and no credible firmware
        # value was filled by an earlier, more-trusted stage. The version string
        # is taken verbatim from the device and never overwrites an existing one.
        if self.explicit_port is None and user and password and not result.firmware_version and \
           result.manufacturer and result.manufacturer.lower() == 'dahua':
            try:
                from .probes.dahua import dahua_firmware_version
            except ImportError:
                from probes.dahua import dahua_firmware_version
            fw = await dahua_firmware_version(ip, user, password, self.timeout)
            if fw:
                result.firmware_version = fw

        # Step 5d: Uniview model via its web RPC (unauthenticated; model only).
        # Rides the device web port (explicit scan port when given), so unlike
        # 5b/5c it is not gated on explicit_port. Only szDeviceName is read.
        if not result.model and result.manufacturer \
                and result.manufacturer.lower() == 'uniview':
            try:
                from .probes.uniview import uniview_device_info
            except ImportError:
                from probes.uniview import uniview_device_info
            uv = await uniview_device_info(ip, self.timeout, port=self.explicit_port)
            if uv and uv.get('model'):
                result.model = uv['model']
                if 'uniview:device_info' not in result.evidence:
                    result.evidence.append('uniview:device_info')

        # Step 5e: Uniview identification via its distinctive web RPC, used only
        # when no stronger signal named a manufacturer and the device was reached.
        # The main-cgi JSON shape is Uniview-specific; it fills manufacturer+model
        # (model only, no credentials/user data). Runs before the weak port guess.
        if not result.manufacturer and result.network_status in ('ok', 'partial'):
            try:
                from .probes.uniview import uniview_identify
            except ImportError:
                from probes.uniview import uniview_identify
            uv = await uniview_identify(ip, self.timeout, port=self.explicit_port)
            if uv:
                result.manufacturer = uv['manufacturer']
                if uv.get('model') and not result.model:
                    result.model = uv['model']
                result.confidence = max(result.confidence, 0.80)
                if 'uniview:main-cgi' not in result.evidence:
                    result.evidence.append('uniview:main-cgi')

        # NOTE: port 34567 alone is NOT sufficient to attribute the Xiongmai chipset
        # (it is a common DVRIP/Sofia port shared by many OEM firmwares). The earlier
        # "open_port:34567 -> chipset Xiongmai" heuristic was removed to avoid
        # unsupported attribution. result.chipset is only set from genuinely
        # chipset-specific evidence (none inferred at scanner level at present).

        # Dahua SDK ports (37777 TCP / 37778 UDP): weak, last-resort guess. Port 37777
        # is NOT exclusive to Dahua (Hikvision devices expose it too), so it runs only
        # when (a) no stronger signal identified a manufacturer and (b) we actually
        # reached the device (network_status ok/partial). If every probe failed
        # (unreachable/unknown) there is no basis for a brand and we stay honestly unknown.
        if (37777 in result.open_ports or 37778 in result.open_ports) \
                and not result.manufacturer \
                and not self._is_proxied \
                and result.network_status in ("ok", "partial"):
            _dahua_port = 37777 if 37777 in result.open_ports else 37778
            result.manufacturer = "Dahua"
            result.confidence = max(result.confidence, 0.40)
            result.evidence.append(f"open_port:{_dahua_port}->dahua-guess")

        # Step 6: URL pattern matching — chipset first, then manufacturer, then generic
        lookup_key = None
        if result.chipset:
            lookup_key = result.chipset.lower()
        elif result.manufacturer:
            lookup_key = result.manufacturer.lower()

        if lookup_key:
            url_patterns = self._get_url_patterns(
                lookup_key,
                result.model.lower() if result.model else None
            )
        else:
            # No manufacturer/chipset: fall back to generic patterns
            url_patterns = self._get_url_patterns('generic', None)

        # Test each pattern and collect working URLs
        # For an explicit ip:port target, URLs are built as host:port so only that port is hit.
        url_host = f"{ip}:{self.explicit_port}" if self.explicit_port is not None else ip
        await self._test_url_patterns(url_host, url_patterns, result, user, password)

        logger.info(f"Scan completed for {ip}: {result}")
        return result

    # TEST-NET-1 (RFC 5737) is reserved for documentation and never routed, so
    # a successful TCP connect to it means something is intercepting our TCP.
    _PROXY_PROBE_IP = "192.0.2.1"

    async def _is_tcp_proxied(self, timeout: float = 2.0) -> bool:
        """
        Detect an outbound TCP proxy / VPN that accepts connections on the
        client's behalf: connect to a random high port on TEST-NET-1. Any
        successful connect there is impossible on a clean network, so it means
        the connection was intercepted. Failure, refusal or timeout means no proxy.
        """
        port = random.randint(20000, 60000)
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._PROXY_PROBE_IP, port),
                timeout=timeout
            )
        except (asyncio.TimeoutError, OSError):
            return False
        except Exception as e:
            logger.debug(f"TCP proxy detection error: {e}")
            return False
        try:
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"TCP proxy detection: close error: {e}")
        logger.info("Outbound TCP appears proxied (connect to TEST-NET-1 succeeded)")
        return True

    async def _check_ports(self, ip: str) -> List[int]:
        """Check which common ports are open on the target IP (TCP connect only).

        Uses a short per-port timeout (min(self.timeout, 3)) and checks the ports
        concurrently, bounded by the scanner semaphore. Result order follows
        self.common_ports.
        """
        port_scan_timeout = min(self.timeout, 3)

        async def check(port: int) -> bool:
            async with self.semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=port_scan_timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    logger.debug(f"Port {port} is open on {ip}")
                    return True
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    logger.debug(f"Port {port} is closed or unreachable on {ip}")
                    return False
                except Exception as e:
                    logger.warning(f"Error checking port {port} on {ip}: {e}")
                    return False

        results = await asyncio.gather(*(check(p) for p in self.common_ports))
        return [p for p, ok in zip(self.common_ports, results) if ok]

    def _determine_protocols(self, open_ports: List[int]) -> List[str]:
        """Determine likely protocols based on open ports."""
        protocol_map = {
            80: "HTTP",
            443: "HTTPS",
            554: "RTSP",
            8000: "HTTP-ALT",
            8080: "HTTP-PROXY",
            34567: "HTTP-HIKVISION",  # Common for Hikvision
            37777: "DAHUA",           # Dahua proprietary TCP (DHIP)
            37778: "DAHUA-UDP"        # Dahua SDK UDP
        }
        protocols = []
        for port in open_ports:
            if port in protocol_map:
                protocols.append(protocol_map[port])
        return protocols

    async def _http_probe(self, ip: str) -> Dict[str, Any]:
        """
        Perform HTTP probe on the target IP.
        Returns a dictionary with any useful information found.
        """
        # Import here to avoid circular imports
        try:
            from .probes.http import http_probe
        except ImportError:
            from probes.http import http_probe
        if self.explicit_port is not None:
            return await http_probe(ip, self.timeout, extra_favicon_paths=self._extra_favicon_paths,
                                    port=self.explicit_port)
        return await http_probe(ip, self.timeout, extra_favicon_paths=self._extra_favicon_paths)

    async def _rtsp_probe(self, ip: str) -> Dict[str, Any]:
        """
        Perform RTSP probe on common RTSP ports.
        Returns a dictionary with any useful information found.
        """
        # Import here to avoid circular imports
        try:
            from .probes.rtsp import rtsp_probe
        except ImportError:
            from probes.rtsp import rtsp_probe
        # Try common RTSP ports
        rank = {"ok": 0, "empty": 1, "refused": 2, "timeout": 3, "unknown": 4}
        best_status = "unknown"
        rtsp_ports = [self.explicit_port] if self.explicit_port is not None else [554, 8554, 10554]
        for port in rtsp_ports:
            result = await rtsp_probe(ip, port, self.timeout)
            if result.get('rtsp_available'):
                return result
            st = (result or {}).get('_status', 'unknown')
            if rank.get(st, 4) < rank[best_status]:
                best_status = st
        return {'_status': best_status}

    async def _gather_fingerprint_data(self, ip: str, open_ports: List[int],
                                      http_info: Dict[str, Any],
                                      rtsp_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gather data for fingerprinting by making specific requests to known endpoints.
        """
        http_info = http_info or {}
        rtsp_info = rtsp_info or {}
        data = {}
        statuses = []
        if http_info:
            statuses.append(http_info.get('_status', 'unknown'))
        if rtsp_info:
            statuses.append(rtsp_info.get('_status', 'unknown'))
        # Add HTTP information
        if http_info:
            data['http_server'] = http_info.get('server', '')
            data['http_www_authenticate'] = http_info.get('www_authenticate', '')
            data['http_html_content'] = http_info.get('html_content', '')
            data['http_favicon_md5'] = http_info.get('favicon_md5')
            data['http_favicon_mmh3'] = http_info.get('favicon_mmh3')
            data['http_favicon_paths'] = http_info.get('favicon_md5_paths') or {}
        # Add RTSP information
        if rtsp_info:
            data['rtsp_server'] = rtsp_info.get('server', '')
            data['rtsp_raw_response'] = rtsp_info.get('raw_response', '')
        # Add port information
        data['open_ports'] = open_ports
        # SSL certificate issuer/subject (stable brand signal) when a TLS port is open
        if 443 in open_ports:
            try:
                from .probes.ssl_cert import ssl_cert_probe
            except ImportError:
                from probes.ssl_cert import ssl_cert_probe
            ssl_info = await ssl_cert_probe(ip, 443, min(self.timeout, 5))
            if ssl_info:
                statuses.append(ssl_info.get('_status', 'unknown'))
                data.update({k: v for k, v in ssl_info.items() if not k.startswith('_')})
        # Try ISAPI if we suspect Hikvision
        # (skipped for an explicit ip:port target: ISAPI would hit default ports)
        if self.explicit_port is None and (
                'hikvision' in str(http_info.get('server', '')).lower() or
                'hikvision' in str(http_info.get('www_authenticate', '')).lower()):
            try:
                from .probes.isapi import isapi_probe
            except ImportError:
                from probes.isapi import isapi_probe
            isapi_data = await isapi_probe(ip, self.timeout)
            data['isapi_data'] = isapi_data
            # Expose the device MAC at the top level, where the fingerprinter reads it
            if isinstance(isapi_data, dict) and isapi_data.get('mac_address') \
                    and not data.get('mac_address'):
                data['mac_address'] = isapi_data['mac_address']
        # ONVIF probe to get device information
        try:
            try:
                from .probes.onvif import onvif_probe, onvif_get_device_info
            except ImportError:
                from probes.onvif import onvif_probe, onvif_get_device_info
            devices = await onvif_probe(timeout=self.timeout)
            # WS-Discovery is multicast and not bound to the target: only accept a
            # device that is actually the scanned IP, otherwise a neighbour's
            # identity would be attributed to the target.
            for dev in devices or []:
                xaddr = dev.get('xaddr')
                if not xaddr or not self._onvif_device_is_target(dev, ip):
                    continue
                dev_info = await onvif_get_device_info(xaddr, timeout=self.timeout)
                if dev_info:
                    # Namespace the keys for the fingerprinter (onvif_manufacturer, ...)
                    for key, value in dev_info.items():
                        okey = f"onvif_{key}"
                        if value and not data.get(okey):
                            data[okey] = value
                    break
        except Exception as e:
            logger.debug(f"ONVIF probe or device info failed: {e}")
        data['_network_status'] = self._aggregate_network_status(statuses)
        return data

    @staticmethod
    def _onvif_device_is_target(dev: Dict[str, Any], ip: str) -> bool:
        """True if a WS-Discovery response came from, or advertises, the target IP."""
        if dev.get('ip') == ip:
            return True
        try:
            from urllib.parse import urlparse
            return urlparse(dev.get('xaddr') or '').hostname == ip
        except ValueError:
            return False

    @staticmethod
    def _aggregate_network_status(statuses: List[str]) -> str:
        """
        Merge probe statuses into a single network status.

        ok: some probe got a real answer. partial: the host answered at the
        transport level (refused / empty) but nothing useful came back.
        unreachable: no probe reached the host (timeouts, no data at all).
        """
        if any(s == "ok" for s in statuses):
            return "ok"
        if any(s in ("refused", "empty") for s in statuses):
            return "partial"
        return "unreachable"

    def _get_url_patterns(self, manufacturer: str, model: Optional[str]) -> Dict[str, List[str]]:
        """
        Load URL patterns for the given manufacturer and model from the YAML database.
        Supports fallback to manufacturer-wide patterns and prefix-based model matching.
        """
        if not self.url_patterns:
            return {'snapshot': [], 'stream': [], 'overlay': []}

        # Try to get manufacturer-specific patterns (case-insensitive)
        manufacturer_patterns = {}
        for key, value in self.url_patterns.items():
            if key.lower() == manufacturer.lower():
                manufacturer_patterns = value
                break

        # If still not found, try exact case as fallback
        if not manufacturer_patterns:
            manufacturer_patterns = self.url_patterns.get(manufacturer, {})

        # If we have a model, try to get model-specific patterns with prefix fallback
        if model and isinstance(manufacturer_patterns, dict):
            # 1. First try exact match
            if model in manufacturer_patterns:
                model_patterns = manufacturer_patterns[model]
                if isinstance(model_patterns, dict):
                    return {
                        'snapshot': model_patterns.get('snapshot', []),
                        'stream': model_patterns.get('stream', []),
                        'overlay': model_patterns.get('overlay', [])
                    }

            # 2. Try prefix-based matching (longest prefix first)
            # Normalize model for comparison (uppercase, no spaces)
            norm_model = model.upper().replace(' ', '')

            # Get all string keys that could be model prefixes (skip special keys like '_default')
            candidate_keys = [k for k in manufacturer_patterns.keys()
                            if isinstance(k, str) and not k.startswith('_')]

            # Sort by length descending to check longest prefixes first
            candidate_keys.sort(key=len, reverse=True)

            for key in candidate_keys:
                norm_key = key.upper().replace(' ', '')
                if norm_model.startswith(norm_key):
                    model_patterns = manufacturer_patterns[key]
                    if isinstance(model_patterns, dict):
                        return {
                            'snapshot': model_patterns.get('snapshot', []),
                            'stream': model_patterns.get('stream', []),
                            'overlay': model_patterns.get('overlay', [])
                        }

        # Fallbacks that apply whether or not a model was given:
        if isinstance(manufacturer_patterns, dict):
            # 3a. Explicit 'default' sub-dict (chipset-style patterns for all models)
            default_patterns = manufacturer_patterns.get('default')
            if isinstance(default_patterns, dict):
                return {
                    'snapshot': default_patterns.get('snapshot', []),
                    'stream': default_patterns.get('stream', []),
                    'overlay': default_patterns.get('overlay', [])
                }
            # 3b. Brand-level categories declared directly on the manufacturer dict
            if any(key in manufacturer_patterns for key in ('snapshot', 'stream', 'overlay')):
                return {
                    'snapshot': manufacturer_patterns.get('snapshot', []),
                    'stream': manufacturer_patterns.get('stream', []),
                    'overlay': manufacturer_patterns.get('overlay', [])
                }

        # If we still don't have patterns, return empty
        return {'snapshot': [], 'stream': [], 'overlay': []}

    def resolve_urls(self, manufacturer: Optional[str] = None, model: Optional[str] = None,
                     chipset: Optional[str] = None, ip: Optional[str] = None,
                     user: str = "", password: str = "") -> Dict[str, List[str]]:
        """Resolve candidate URL patterns for a device WITHOUT scanning.

        Lookup priority matches scan(): chipset -> manufacturer -> generic.
        If `ip` is given, the {ip}/{user}/{pass} placeholders are filled in;
        otherwise the raw templates (with placeholders) are returned.
        Returns a dict with keys 'snapshot', 'stream', 'overlay'.
        """
        if chipset:
            lookup_key = chipset.lower()
        elif manufacturer:
            lookup_key = manufacturer.lower()
        else:
            lookup_key = 'generic'
        patterns = self._get_url_patterns(lookup_key, model.lower() if model else None)
        if ip is None:
            return patterns
        filled = {}
        for kind, plist in patterns.items():
            urls = []
            for pattern in plist:
                u = self._format_url(pattern, ip, user, password)
                if u:
                    urls.append(u)
            filled[kind] = urls
        return filled

    async def _test_url_patterns(self, ip: str, url_patterns: Dict[str, List[str]],
                                 result: CameraInfo, user: str = "", password: str = "") -> None:
        """
        Test URL patterns for the target IP concurrently and collect those that
        respond. Classification is unchanged: HTTP 2xx -> working bucket;
        401/403 -> requires_auth_urls; RTSP uses _check_rtsp_url verdicts.

        Concurrency is bounded by self.url_test_concurrency (one target IP).
        Stream checks stop being started once two working stream URLs are found.
        """
        sem = asyncio.Semaphore(self.url_test_concurrency)
        lock = asyncio.Lock()
        stop = {"stream": False}
        # A dead URL should not block the scan for the full global timeout
        url_timeout = min(self.timeout, 3)

        async def _add_stream(url: str) -> None:
            async with lock:
                if not stop["stream"]:
                    result.stream_urls.append(url)
                    if len(result.stream_urls) >= 2:
                        stop["stream"] = True

        async def _check(pattern: str, kind: str) -> None:
            if kind == "stream":
                async with lock:
                    if stop["stream"]:
                        return
            async with sem:
                # Re-check the stop condition after acquiring the semaphore: a
                # stream task may have queued here while under the limit, but the
                # limit can be reached before it runs. Avoid starting new stream
                # requests once enough working streams are known.
                if kind == "stream":
                    async with lock:
                        if stop["stream"]:
                            return
                url = self._format_url(pattern, ip, user, password)
                if not url:
                    return
                try:
                    if url.startswith('rtsp://'):
                        # Preserve existing RTSP verdict handling
                        verdict = await self._check_rtsp_url(ip, url, url_timeout, user, password)
                        if verdict == "ok":
                            await _add_stream(url)
                        elif verdict == "auth_required":
                            async with lock:
                                result.requires_auth_urls.append(url)
                        # "unreachable" → not recorded
                    else:
                        status = await check_http_endpoint(ip, url, url_timeout, user, password)
                        if status is None:
                            return
                        if 200 <= status < 300:
                            if kind == "stream":
                                await _add_stream(url)
                            elif kind == "snapshot":
                                async with lock:
                                    result.snapshot_urls.append(url)
                            elif kind == "overlay":
                                async with lock:
                                    result.osd_urls.append(url)
                        elif status in (401, 403):
                            async with lock:
                                result.requires_auth_urls.append(url)
                except Exception:
                    return

        tasks = []
        for pattern in url_patterns.get('stream', []):
            tasks.append(_check(pattern, 'stream'))
        for pattern in url_patterns.get('snapshot', []):
            tasks.append(_check(pattern, 'snapshot'))
        for pattern in url_patterns.get('overlay', []):
            tasks.append(_check(pattern, 'overlay'))

        await asyncio.gather(*tasks, return_exceptions=True)

    def _format_url(self, pattern: str, ip: str, user: str = "", password: str = "") -> Optional[str]:
        """
        Format a URL pattern by replacing placeholders.

        {user}/{pass} are URL-encoded. Empty credentials substitute to empty
        strings (Mode 1 behaviour, e.g. "rtsp://:@ip/...").
        """
        try:
            # Replace {ip} with the actual IP
            formatted = pattern.replace('{ip}', ip)
            # Replace {user}/{pass} with URL-encoded credentials (empty if not provided)
            formatted = formatted.replace('{user}', quote(user or '', safe=''))
            formatted = formatted.replace('{pass}', quote(password or '', safe=''))
            # iSpyConnect-style bracket placeholders (case-insensitive). Lambdas keep
            # the substituted text literal (no backslash/group interpretation).
            q_user, q_pass = quote(user or '', safe=''), quote(password or '', safe='')
            for token, value in (('USERNAME', q_user), ('PASSWORD', q_pass),
                                 ('CHANNEL', '1'), ('WIDTH', '640'),
                                 ('HEIGHT', '480'), ('AUTH', '')):
                formatted = re.sub(r'\[' + token + r'\]', lambda _m, v=value: v,
                                   formatted, flags=re.I)
            # Collapse duplicate slashes in the path while preserving the scheme's "://"
            formatted = re.sub(r'(?<!:)//+', '/', formatted)
            return formatted
        except Exception as e:
            logger.debug(f"Error formatting URL pattern {pattern}: {e}")
            return None

    async def _check_rtsp_url(self, ip: str, url: str, timeout: int,
                              user: str = "", password: str = "") -> str:
        """
        Verify an RTSP URL via DESCRIBE, authenticating with raw credentials when
        supplied. Returns an RTSP verdict (RTSP_OK / RTSP_AUTH_REQUIRED /
        RTSP_UNREACHABLE). Any embedded credentials in `url` are stripped for the
        request URI; raw `user`/`password` are used for the auth header (no
        double-encoding, and the credential-bearing URL is never logged).
        """
        try:
            from .probes.rtsp import rtsp_check_stream, RTSP_UNREACHABLE
        except ImportError:
            from probes.rtsp import rtsp_check_stream, RTSP_UNREACHABLE

        try:
            if not url.startswith('rtsp://'):
                return RTSP_UNREACHABLE
            url_part = url[len('rtsp://'):]

            # Strip embedded credentials (user:pass@) for a clean request URI
            if '@' in url_part:
                _, host_part = url_part.split('@', 1)
            else:
                host_part = url_part

            # Split host[:port] from the path
            if '/' in host_part:
                authority, path = host_part.split('/', 1)
                path = '/' + path
            else:
                authority, path = host_part, ''

            if ':' in authority:
                host, port_str = authority.split(':', 1)
                port = int(port_str)
            else:
                host = authority
                port = 554  # Default RTSP port

            clean_uri = f"rtsp://{host}:{port}{path}"
            return await rtsp_check_stream(host, clean_uri, port, timeout, user, password)
        except Exception as e:
            # Log host:port only — never the credential-bearing URL
            logger.debug(f"Error checking RTSP stream on {ip}: {e}")
            return RTSP_UNREACHABLE


def parse_target(s: str) -> tuple:
    """Accept 'ip', 'ip:port', 'host:port'. Reject ports outside 1..65535.

    Returns (host, port_or_None). A string with more than one ':' is treated as
    IPv6 and returned unchanged.
    """
    if ":" in s and s.count(":") == 1:
        host, port_s = s.rsplit(":", 1)
        try:
            port = int(port_s)
            if not (host and 1 <= port <= 65535):
                raise ValueError
        except ValueError:
            raise SystemExit(f"Invalid target or port in '{s}'")
        return host, port
    return s, None


def parse_ports(s: str) -> List[int]:
    """Parse '80,8080,7102' into a list of ports; reject anything outside 1..65535."""
    ports = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise SystemExit(f"Invalid port '{part}' in --ports")
        if port not in ports:
            ports.append(port)
    return ports


def format_result(info: "CameraInfo") -> str:
    """Render a CameraInfo as a readable, sectioned report for the CLI."""
    d = info.model_dump() if hasattr(info, "model_dump") else dict(info)

    def field(label, value):
        return f"  {label:<13}: {value}"

    dash = "\u2014"
    lines = [f"=== Scan result: {d.get('ip')} ==="]
    net = d.get("network_status") or "unknown"
    proxied = bool(d.get("tcp_proxied"))
    net_label = net + (" (behind TCP proxy \u2014 port data unreliable)" if proxied else "")
    lines.append(field("Network", net_label))
    ports_text = ", ".join(map(str, d.get("open_ports") or [])) or dash
    if net == "unreachable":
        lines.append(field("Result", "could not contact device"))
        lines.append(field("Open ports", ports_text
                           + ("  (proxy-inflated)" if proxied else "  (from port scan only)")))
        return "\n".join(lines)
    lines.append(field("Manufacturer", d.get("manufacturer") or dash))
    if d.get("chipset"):
        lines.append(field("Chipset", d["chipset"]))
    lines.append(field("Model", d.get("model") or dash))
    lines.append(field("Firmware", d.get("firmware_version") or dash))
    if d.get("serial_number"):
        lines.append(field("Serial", d["serial_number"]))
    lines.append(field("Confidence", f"{d.get('confidence', 0.0):.2f}"))
    lines.append(field("Open ports", ports_text + ("  (proxy-inflated)" if proxied else "")))
    lines.append(field("Protocols", ", ".join(d.get("protocols") or []) or dash))
    lines.append(field("Evidence", ", ".join(d.get("evidence") or []) or dash))

    def section(title, key):
        urls = d.get(key) or []
        if not urls:
            return
        lines.append(f"  {title} ({len(urls)}):")
        for u in urls:
            lines.append(f"    - {u}")

    section("Stream URLs", "stream_urls")
    section("Snapshot URLs", "snapshot_urls")
    section("OSD URLs", "osd_urls")
    section("Needs auth", "requires_auth_urls")
    return "\n".join(lines)


# Example usage (for testing)
if __name__ == "__main__":
    import argparse
    import asyncio
    import sys

    parser = argparse.ArgumentParser(description='Scan an IP address for IP cameras.')
    parser.add_argument('ip', nargs='?', help='Target IP address or ip:port to scan (ip:port scans only that port)')
    parser.add_argument('--resolve', '--resolve-manufacturer', metavar='BRAND',
                        help='Offline mode: list candidate URLs for BRAND (no scan). Use "generic" for brand-less patterns')
    parser.add_argument('--ip', dest='ip_opt', default=None,
                        help='Target IP for --resolve (same as the positional ip)')
    parser.add_argument('--model', default=None, help='Model for --resolve (optional)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds for each probe (default: 10)')
    parser.add_argument('--semaphore', type=int, default=50, help='Max concurrent requests (default: 50)')
    parser.add_argument('--user', default='', help='Username for authenticated probes (optional)')
    parser.add_argument('--password', default='', help='Password for authenticated probes (optional)')
    parser.add_argument('--concurrency', type=int, default=10, help='Max concurrent URL checks per target (default: 10)')
    parser.add_argument('--ports', default='',
                        help='Extra TCP ports to check, comma-separated (e.g. 7102,9001)')
    parser.add_argument('--json', action='store_true', help='Output raw JSON instead of the formatted report')
    args = parser.parse_args()
    if args.ip_opt:
        if args.ip and args.ip != args.ip_opt:
            parser.error("give the target either as positional ip or --ip, not both")
        args.ip = args.ip_opt
    if not args.resolve and not args.ip:
        parser.error("ip is required unless --resolve BRAND is given")

    if args.resolve:
        # Offline URL lookup: with a positional ip the placeholders are filled in.
        scanner = CameraScanner()
        urls = scanner.resolve_urls(manufacturer=args.resolve, model=args.model,
                                    ip=parse_target(args.ip)[0] if args.ip else None,
                                    user=args.user, password=args.password)
        if args.json:
            import json
            print(json.dumps(urls, ensure_ascii=False, indent=2))
        else:
            print(f"=== URL candidates: {args.resolve}" + (f" {args.model}" if args.model else "") + " ===")
            for kind, plist in urls.items():
                print(f"  {kind} ({len(plist)}):")
                for u in plist:
                    print(f"    {u}")
        sys.exit(0)

    async def main():
        host, explicit_port = parse_target(args.ip)
        scanner = CameraScanner(timeout=args.timeout, semaphore_size=args.semaphore,
                                user=args.user, password=args.password,
                                url_test_concurrency=args.concurrency,
                                port=explicit_port,
                                extra_ports=parse_ports(args.ports))
        result = await scanner.scan(host)
        if args.json:
            import json
            print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2, default=str))
        else:
            print(format_result(result))

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)