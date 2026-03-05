from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
import asyncio
import aiohttp
import ssl
import json
import random
import traceback
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ────────────────────────────────────────────────
# CONSTANTS (same as before)
# ────────────────────────────────────────────────

INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

PLATFORM_NAMES = {
    '1': 'Facebook', '2': 'VK', '3': 'Facebook',
    '4': 'Guest', '7': 'Apple', '8': 'Google',
    '9': 'Twitter', '10': 'Garena', '11': 'Huawei',
    '13': 'Samsung', '17': 'Line',
}

# ────────────────────────────────────────────────
# PROTOBUF & CRYPTO (same minimal version)
# ────────────────────────────────────────────────

class ProtoWriter:
    @staticmethod
    def varint(value):
        result = []
        while value > 127:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)

    @staticmethod
    def tag(field_num, wire_type):
        return ProtoWriter.varint((field_num << 3) | wire_type)

    @staticmethod
    def write_varint(field_num, value):
        return ProtoWriter.tag(field_num, 0) + ProtoWriter.varint(value)

    @staticmethod
    def write_string(field_num, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        return ProtoWriter.tag(field_num, 2) + ProtoWriter.varint(len(value)) + value

    @staticmethod
    def write_message(field_num, data):
        return ProtoWriter.tag(field_num, 2) + ProtoWriter.varint(len(data)) + data

    @staticmethod
    def create_message(fields):
        result = bytearray()
        for field_num, value in sorted(fields.items()):
            if isinstance(value, int):
                result.extend(ProtoWriter.write_varint(field_num, value))
            elif isinstance(value, (str, bytes)):
                result.extend(ProtoWriter.write_string(field_num, value))
            elif isinstance(value, dict):
                msg = ProtoWriter.create_message(value)
                result.extend(ProtoWriter.write_message(field_num, msg))
        return bytes(result)


class ProtoReader:
    @staticmethod
    def read_varint(data, offset=0):
        result = 0
        shift = 0
        while True:
            byte = data[offset]
            result |= (byte & 0x7F) << shift
            offset += 1
            if not (byte & 0x80):
                break
            shift += 7
        return result, offset

    @staticmethod
    def parse_message(data):
        result = {}
        offset = 0
        while offset < len(data):
            try:
                tag, offset = ProtoReader.read_varint(data, offset)
                field_num = tag >> 3
                wire_type = tag & 0x7
                if wire_type == 0:
                    value, offset = ProtoReader.read_varint(data, offset)
                    result[field_num] = value
                elif wire_type == 2:
                    length, offset = ProtoReader.read_varint(data, offset)
                    value = data[offset:offset + length]
                    offset += length
                    try:
                        result[field_num] = value.decode('utf-8')
                    except:
                        result[field_num] = value
                else:
                    break
            except:
                break
        return result


def encrypt_payload(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))


def build_major_login_payload(open_id: str, access_token: str, platform: str) -> bytes:
    p = str(platform)
    random_ip = f"223.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    random_device = f"Google|{random.randint(10000000, 99999999)}"

    fields = {
        3: datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        4: "free fire",
        5: 1,
        7: "1.120.2",
        8: "RIZER OSSSSSS FUCKKKKK56)",
        9: "Handheld",
        10: "Verizon",
        11: "WIFI",
        12: 1920,
        13: 1080,
        14: "280",
        15: "ARM64 HOLY SHITTT| 4",
        16: 4096,
        17: "Adreno (TM) 640",
        18: "OpenGL ES 3.2 v1.46",
        19: random_device,
        20: random_ip,
        21: "en",
        22: open_id,
        23: p,
        24: "Handheld",
        25: {6: 55, 8: 81},
        29: access_token,
        30: 1,
        41: "Verizon",
        42: "WIFI",
        57: "JOHNY JOHNY YES PAAPA",
        60: 36235, 61: 31335, 62: 2519, 63: 703,
        64: 25010, 65: 26628, 66: 32992, 67: 36235,
        73: 3,
        74: "/data/arm64",
        76: 1,
        77: "5b892aaabd688e571f688053118a162b|/data/app/hmmmmmmmsksksksk-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk",
        78: 3,
        79: 2,
        81: "64",
        83: "2019118695",
        86: "OpenGLES2",
        87: 16383,
        88: 4,
        89: b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg==",
        90: random.randint(10000, 15000),
        91: "android",
        92: "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY=",
        95: 110009,
        97: 1,
        98: 0,
        99: p,
        100: p,
    }
    return ProtoWriter.create_message(fields)


# ────────────────────────────────────────────────
# FASTAPI APP
# ────────────────────────────────────────────────

app = FastAPI()


@app.get("/freeFire&ban", response_class=HTMLResponse)
async def ban_page(request: Request):
    access_token = request.query_params.get("accessToken")

    if not access_token:
        return """
        <html>
        <head>
            <title>API</title>
            <style>
                body { margin:0; padding:0; height:100vh; background:#000; color:#fff; font-family:monospace; display:flex; align-items:center; justify-content:center; }
                .box { text-align:center; }
            </style>
        </head>
        <body>
            <div class="box">
                <h2>accessToken missing</h2>
                <p>example: ?accessToken=eyJh...</p>
            </div>
        </body>
        </html>
        """

    try:
        result = await run_ban_logic(access_token)

        if result["success"]:
            content = f"""
*_"-!' BAN SUCCESSFUL !'-_"*  
──────────────────────────────
Platform : {result['platform_name']}
UID      : {result['uid']}
Region   : {result['region']}
──────────────────────────────
            """.strip()
        else:
            content = f"""
*_"-!' BAN FAILED !'-_"*  
──────────────────────────────
Reason : {result.get('reason', 'Unknown error')}
──────────────────────────────
            """.strip()

        full_output = f"""
        <html>
        <head>
            <title>Result</title>
            <style>
                body {{
                    margin:0;
                    padding:0;
                    height:100vh;
                    background:#ffffff;
                    color:#000000;
                    font-family:monospace;
                    font-size:16px;
                    display:flex;
                    flex-direction:column;
                    align-items:center;
                    justify-content:center;
                    text-align:center;
                    white-space:pre;
                    line-height:1.5;
                }}
                .content {{ max-width:600px; padding:20px; }}
                .footer {{
                    position:fixed;
                    bottom:15px;
                    font-size:13px;
                    color:#555;
                }}
            </style>
        </head>
        <body>
            <div class="content">
{content}
            </div>
            <div class="footer">
Developer :- @WHITExTRUSTED
            </div>
        </body>
        </html>
        """

        return HTMLResponse(full_output)

    except Exception as e:
        error_text = f"Error occurred\n{str(e)[:200]}"
        return HTMLResponse(f"""
        <html>
        <head><title>Error</title></head>
        <body style="margin:0;height:100vh;background:#fff;color:#000;display:flex;align-items:center;justify-content:center;font-family:monospace;white-space:pre;">
            <div style="text-align:center;">
{error_text}

Developer :- @WHITExTRUSTED
            </div>
        </body>
        </html>
        """, status_code=500)


async def run_ban_logic(access_token: str) -> dict:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    timeout = aiohttp.ClientTimeout(total=25)
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        # Inspect
        async with session.get(f"{INSPECT_URL}?token={access_token}") as r:
            if r.status != 200:
                return {"success": False, "reason": f"HTTP {r.status}"}
            data = await r.json()
            open_id = data.get("open_id")
            platform = str(data.get("platform", "4"))

            if not open_id:
                return {"success": False, "reason": "Invalid token"}

        platform_name = PLATFORM_NAMES.get(platform, f"Platform-{platform}")

        # Major Login payload
        payload = build_major_login_payload(open_id, access_token, platform)
        encrypted = encrypt_payload(payload)

        ml_headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        async with session.post(MAJOR_LOGIN_URL, data=encrypted, headers=ml_headers) as r:
            if r.status != 200:
                return {"success": False, "reason": f"MajorLogin HTTP {r.status}"}
            major_raw = await r.read()

        major = ProtoReader.parse_message(major_raw)
        uid = major.get(1, 0)
        region = major.get(2, "")

        if not uid:
            return {"success": False, "reason": "No UID received"}

        return {
            "success": True,
            "uid": uid,
            "region": region,
            "platform_name": platform_name,
        }


# For local testing (optional)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)