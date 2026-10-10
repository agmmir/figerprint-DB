"""
ONVIF WS-Discovery and device information probing for IP cameras.
"""

import asyncio
import logging
import socket
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# ONVIF WS-Discovery multicast address and port
ONVIF_MULTICAST_ADDRESS = "239.255.255.250"
ONVIF_PORT = 3702

# ONVIF WS-Discovery Probe message (XML)
ONVIF_PROBE_MESSAGE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:tns="http://www.onvif.org/ver10/network/wsdl">
    <e:Header>
        <w:MessageID>urn:uuid:{message_id}</w:MessageID>
        <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
        <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
    </e:Header>
    <e:Body>
        <d:Probe>
            <d:Types>tns:NetworkVideoTransmitter</d:Types>
        </d:Probe>
    </e:Body>
</e:Envelope>
""".replace("Probe", "Probe")  # already correct

# ONVIF GetDeviceInformation request (SOAP)
ONVIF_GET_DEVICE_INFO = """<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
              xmlns:tns="http://www.onvif.org/ver10/device/wsdl">
    <env:Body>
        <tns:GetDeviceInformation/>
    </env:Body>
</env:Envelope>
"""

async def onvif_probe(timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Perform ONVIF WS-Discovery probe to discover ONVIF devices on the local network.

    Note: This requires multicast support and only works on the local network segment.

    Args:
        timeout: How long to listen for responses in seconds

    Returns:
        List of dictionaries containing information about discovered devices
    """
    devices = []
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)

        # Bind to multicast port to receive responses
        sock.bind(('', ONVIF_PORT))

        # Join multicast group
        group = socket.inet_aton(ONVIF_MULTICAST_ADDRESS)
        mreq = group + socket.inet_aton('0.0.0.0')
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Generate a unique message ID
        import uuid
        message_id = uuid.uuid4()
        message = ONVIF_PROBE_MESSAGE.format(message_id=message_id)

        # Send the probe message to the multicast group
        sock.sendto(message.encode('utf-8'), (ONVIF_MULTICAST_ADDRESS, ONVIF_PORT))

        # Listen for responses
        loop = asyncio.get_event_loop()
        while True:
            try:
                # Use asyncio to wait for data with timeout
                data, addr = await loop.sock_recvfrom(sock, 4096)
                response = data.decode('utf-8', errors='ignore')

                # Parse the response (simplified)
                device_info = _parse_onvif_response(response, addr[0])
                if device_info:
                    devices.append(device_info)

            except asyncio.TimeoutError:
                break
            except Exception as e:
                logger.debug(f"ONVIF probe receive error: {e}")
                break

        sock.close()
    except Exception as e:
        logger.warning(f"ONVIF probe failed: {e}")
        if 'sock' in locals():
            sock.close()

    return devices

def _parse_onvif_response(response: str, source_ip: str) -> Optional[Dict[str, Any]]:
    """
    Parse ONVIF WS-Discovery response to extract device information.
    This is a simplified parser - a full implementation would use XML parsing.
    """
    info = {'ip': source_ip}

    # Look for endpoint references
    if 'http://schemas.xmlsoap.org/ws/2004/08/addressing' in response:
        info['onvif_capable'] = True

    # Extract device type (very basic)
    if 'NetworkVideoTransmitter' in response:
        info['device_type'] = 'NetworkVideoTransmitter'
    elif 'NetworkVideoDisplay' in response:
        info['device_type'] = 'NetworkVideoDisplay'
    elif 'NetworkAudioInput' in response:
        info['device_type'] = 'NetworkAudioInput'

    # Extract scopes if present
    import re
    scopes_match = re.search('<wsdd:Scopes>(.*?)</wsdd:Scopes>', response, re.DOTALL | re.IGNORECASE)
    if scopes_match:
        scopes_text = scopes_match.group(1)
        # Extract individual scope items
        scope_items = re.findall(r'<[^>]+>[^<]*?(?:onvif://www.onvif.org/name/[^<]+|onvif://www.onvif.org/type/[^<]+|onvif://www.onvif.org/hardware/[^<]+)[^<]*?</[^>]+>', scopes_text)
        if scope_items:
            info['scopes'] = [item.strip('<>/') for item in scope_items]

    # Extract XAddrs
    xaddrs_match = re.search('<wsdd:XAddrs>(.*?)</wsdd:XAddrs>', response, re.DOTALL | re.IGNORECASE)
    if xaddrs_match:
        xaddrs_text = xaddrs_match.group(1).strip()
        # Take the first address
        first_addr = xaddrs_text.split()[0] if xaddrs_text else ''
        if first_addr:
            info['xaddr'] = first_addr

    return info if info.get('onvif_capable') else None

async def onvif_get_device_info(xaddr: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Perform ONVIF GetDeviceInformation request to get device details.

    Args:
        xaddr: The ONVIF device address (e.g., http://host:port/onvif/device_service)
        timeout: Request timeout in seconds

    Returns:
        Dictionary with Manufacturer, Model, FirmwareVersion, SerialNumber if successful,
        otherwise empty dict.
    """
    info = {}
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            # Send SOAP request
            headers = {
                'Content-Type': 'application/soap+xml; charset=utf-8',
                'SOAPAction': 'http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation'
            }
            async with session.post(xaddr, data=ONVIF_GET_DEVICE_INFO, headers=headers, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text(encoding='utf-8', errors='ignore')
                    # Parse XML response
                    root = ET.fromstring(text)
                    # Define namespaces
                    ns = {
                        'env': 'http://www.w3.org/2003/05/soap-envelope',
                        'tns': 'http://www.onvif.org/ver10/device/wsdl'
                    }
                    # Find Manufacturer
                    manufacturer_elem = root.find('.//tns:Manufacturer', ns)
                    if manufacturer_elem is not None and manufacturer_elem.text:
                        info['manufacturer'] = manufacturer_elem.text.strip()
                    # Find Model
                    model_elem = root.find('.//tns:Model', ns)
                    if model_elem is not None and model_elem.text:
                        info['model'] = model_elem.text.strip()
                    # Find FirmwareVersion
                    firmware_elem = root.find('.//tns:FirmwareVersion', ns)
                    if firmware_elem is not None and firmware_elem.text:
                        info['firmware'] = firmware_elem.text.strip()
                    # Find SerialNumber
                    serial_elem = root.find('.//tns:SerialNumber', ns)
                    if serial_elem is not None and serial_elem.text:
                        info['serial'] = serial_elem.text.strip()
                else:
                    logger.debug(f"ONVIF GetDeviceInformation failed with status {resp.status} for {xaddr}")
    except Exception as e:
        logger.debug(f"ONVIF GetDeviceInformation error for {xaddr}: {e}")
    return info