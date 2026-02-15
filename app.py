import asyncio
import time
import httpx
import json
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB52"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}
TOKEN_API_URL = "https://aman-jwt-api-live.vercel.app/api/token"

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> Tuple[str, str]:
    r = region.upper()
    if r == "IND":
        return ("4495621455", "SOLANKI-HAX_O44EG_BY_SPIDEERIO_GAMING_Q4016")
    elif r in {"BR", "US", "SAC", "NA"}:
        return ("4503332828", "SOLANKI-BR_T2WYE_BY_SPIDEERIO_GAMING_710IX")
    else:
        return ("3882454173", "F3153992BA2CACDA590E96778C424FDE6BA7E372EB1D3A0DD28F11BCAA02EE37")


# === Token Generation ===
async def get_jwt_token(region: str):
    uid, password = get_account_credentials(region)
    url = f"{TOKEN_API_URL}?uid={uid}&password={password}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        data = resp.json()
        return f"Bearer {data.get('token', '0')}", data.get('serverUrl', '0')

async def initialize_tokens():
    tasks = [get_jwt_token(r) for r in SUPPORTED_REGIONS]
    results = await asyncio.gather(*tasks)
    for region, (token, server_url) in zip(SUPPORTED_REGIONS, results):
        cached_tokens[region] = {
            'token': token,
            'server_url': server_url,
            'expires_at': time.time() + 25200  # 7 hours
        }

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)  # Refresh every 7 hours
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str]:
    region = region.upper()
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['server_url']
    token, server_url = await get_jwt_token(region)
    cached_tokens[region] = {
        'token': token,
        'server_url': server_url,
        'expires_at': time.time() + 25200
    }
    return token, server_url

async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, server = await get_token_info(region)
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue",
        'Authorization': token, 
        'X-Unity-Version': "2018.4.11f1", 
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

def format_response(data):
    basic_info = data.get("basicInfo", {})
    profile_info = data.get("profileInfo", {})
    prime_level = basic_info.get("primeLevel", {})
    clan_info = data.get("clanBasicInfo", {})
    captain_info = data.get("captainBasicInfo", {})
    social_info = data.get("socialInfo", {})
    credit_info = data.get("creditScoreInfo", {})
    pet_info = data.get("petInfo", {})
    
    return {
        "AccountInfo": data.get("basicInfo", {}),
        "AccountProfileInfo": data.get("profileInfo", {}),
        "primeLevel": basic_info.get("primeLevel"),
        "GuildInfo": data.get("clanBasicInfo", {}),
        "CaptainInfo": data.get("captainBasicInfo", {}),
        "CreditScoreInfo": data.get("creditScoreInfo", {}),
        "PetInfo": data.get("petInfo", {}),
        "SocialInfo": data.get("socialInfo", {}),
        "CraftlandInfo": data.get("workshop_maps", {})
    }

# === API Routes ===
@app.route('/player-info')
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')
    if not uid or not region:
        return jsonify({"error": "Please provide UID and REGION."}), 400
    try:
        return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        formatted = format_response(return_data)
        return jsonify(formatted), 200
    except Exception as e:
        return jsonify({"error": f"Invalid UID or Region. Please check and try again. Error: {str(e)}"}), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {str(e)}'}), 500

# === Startup ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)
