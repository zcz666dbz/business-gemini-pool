"""Business Gemini OpenAPI 兼容服务
整合JWT获取和聊天功能，提供OpenAPI接口
支持多账号轮训
"""

import json
import os
import time
import hmac
import hashlib
import base64
import uuid
import threading
import requests
from pathlib import Path
from datetime import datetime
from flask import Flask, request, Response, jsonify, send_from_directory
from flask_cors import CORS

# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置
CONFIG_FILE = Path(__file__).parent / "business_gemini_session.json"

# API endpoints
BASE_URL = "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global"
CREATE_SESSION_URL = f"{BASE_URL}/widgetCreateSession"
STREAM_ASSIST_URL = f"{BASE_URL}/widgetStreamAssist"
GETOXSRF_URL = "https://business.gemini.google/auth/getoxsrf"

# Flask应用
app = Flask(__name__, static_folder='.')
CORS(app)

# 环境变量控制的鉴权配置
ADMIN_AUTH_KEY = os.getenv("WEB_ADMIN_AUTH_KEY")
ADMIN_AUTH_USER = os.getenv("WEB_ADMIN_AUTH_USER", "admin")
ADMIN_AUTH_REALM = os.getenv("WEB_ADMIN_AUTH_REALM", "Business Gemini Admin")
API_AUTH_KEY = os.getenv("API_AUTH_KEY")

ADMIN_PROTECTED_PATHS = {'/', '/index.html', '/chat_history.html'}
ADMIN_PROTECTED_PREFIXES = ('/api/',)


def _is_admin_path(path: str) -> bool:
    if path in ADMIN_PROTECTED_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in ADMIN_PROTECTED_PREFIXES)


def _admin_auth_required():
    if not ADMIN_AUTH_KEY:
        return None
    auth = request.authorization
    if auth:
        username = auth.username or ""
        password = auth.password or ""
        username_valid = True
        if ADMIN_AUTH_USER:
            username_valid = hmac.compare_digest(username, ADMIN_AUTH_USER)
        if username_valid and hmac.compare_digest(password, ADMIN_AUTH_KEY):
            return None
    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": f'Basic realm="{ADMIN_AUTH_REALM}"'}
    )


def _api_auth_required():
    if not API_AUTH_KEY:
        return None
    provided_key = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        provided_key = auth_header[7:].strip()
    if not provided_key:
        provided_key = request.headers.get("X-API-Key")
    if provided_key and hmac.compare_digest(provided_key, API_AUTH_KEY):
        return None
    return jsonify({
        "error": "invalid_api_key",
        "message": "Invalid or missing API key"
    }), 401


@app.before_request
def enforce_authentication():
    if request.method == 'OPTIONS':
        return None
    path = request.path or '/'
    if ADMIN_AUTH_KEY and _is_admin_path(path):
        response = _admin_auth_required()
        if response is not None:
            return response
    if API_AUTH_KEY and path.startswith('/v1/'):
        response = _api_auth_required()
        if response is not None:
            return response


class AccountManager:
    """多账号管理器，支持轮训策略"""
    
    def __init__(self):
        self.config = None
        self.accounts = []  # 账号列表
        self.current_index = 0  # 当前轮训索引
        self.account_states = {}  # 账号状态: {index: {jwt, jwt_time, session, available}}
        self.lock = threading.Lock()
    
    def load_config(self):
        """加载配置"""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                self.config = json.load(f)
                self.accounts = self.config.get("accounts", [])
                # 初始化账号状态
                for i, acc in enumerate(self.accounts):
                    available = acc.get("available", True)  # 默认可用
                    self.account_states[i] = {
                        "jwt": None,
                        "jwt_time": 0,
                        "session": None,
                        "available": available
                    }
        return self.config
    
    def save_config(self):
        """保存配置到文件"""
        if self.config and CONFIG_FILE.exists():
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
    
    def mark_account_unavailable(self, index: int, reason: str = ""):
        """标记账号不可用"""
        with self.lock:
            if 0 <= index < len(self.accounts):
                self.accounts[index]["available"] = False
                self.accounts[index]["unavailable_reason"] = reason
                self.accounts[index]["unavailable_time"] = datetime.now().isoformat()
                self.account_states[index]["available"] = False
                self.save_config()
                print(f"[!] 账号 {index} 已标记为不可用: {reason}")
    
    def get_available_accounts(self):
        """获取可用账号列表"""
        return [(i, acc) for i, acc in enumerate(self.accounts) 
                if self.account_states.get(i, {}).get("available", True)]
    
    def get_next_account(self):
        """轮训获取下一个可用账号"""
        with self.lock:
            available = self.get_available_accounts()
            if not available:
                raise Exception("没有可用的账号")
            
            # 轮训选择
            self.current_index = self.current_index % len(available)
            idx, account = available[self.current_index]
            self.current_index = (self.current_index + 1) % len(available)
            return idx, account
    
    def get_account_count(self):
        """获取账号数量统计"""
        total = len(self.accounts)
        available = len(self.get_available_accounts())
        return total, available


# 全局账号管理器
account_manager = AccountManager()


def check_proxy(proxy: str) -> bool:
    """检测代理是否可用"""
    if not proxy:
        return False
    try:
        proxies = {"http": proxy, "https": proxy}
        resp = requests.get("https://www.google.com", proxies=proxies, 
                          verify=False, timeout=10)
        return resp.status_code == 200
    except:
        return False


def url_safe_b64encode(data: bytes) -> str:
    """URL安全的Base64编码，不带padding"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def kq_encode(s: str) -> str:
    """模拟JS的kQ函数"""
    byte_arr = bytearray()
    for char in s:
        val = ord(char)
        if val > 255:
            byte_arr.append(val & 255)
            byte_arr.append(val >> 8)
        else:
            byte_arr.append(val)
    return url_safe_b64encode(bytes(byte_arr))


def decode_xsrf_token(xsrf_token: str) -> bytes:
    """将 xsrfToken 解码为字节数组（用于HMAC签名）"""
    padding = 4 - len(xsrf_token) % 4
    if padding != 4:
        xsrf_token += '=' * padding
    return base64.urlsafe_b64decode(xsrf_token)


def create_jwt(key_bytes: bytes, key_id: str, csesidx: str) -> str:
    """创建JWT token"""
    now = int(time.time())

    header = {
        "alg": "HS256",
        "typ": "JWT",
        "kid": key_id
    }

    payload = {
        "iss": "https://business.gemini.google",
        "aud": "https://biz-discoveryengine.googleapis.com",
        "sub": f"csesidx/{csesidx}",
        "iat": now,
        "exp": now + 300,
        "nbf": now
    }

    header_b64 = kq_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = kq_encode(json.dumps(payload, separators=(',', ':')))
    message = f"{header_b64}.{payload_b64}"

    signature = hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).digest()
    signature_b64 = url_safe_b64encode(signature)

    return f"{message}.{signature_b64}"


def get_jwt_for_account(account: dict, proxy: str) -> str:
    """为指定账号获取JWT"""
    secure_c_ses = account.get("secure_c_ses")
    host_c_oses = account.get("host_c_oses")
    csesidx = account.get("csesidx")

    if not secure_c_ses or not csesidx:
        raise ValueError("缺少 secure_c_ses 或 csesidx")

    url = f"{GETOXSRF_URL}?csesidx={csesidx}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    headers = {
        "accept": "*/*",
        "user-agent": account.get('user_agent', 'Mozilla/5.0'),
        "cookie": f'__Secure-C_SES={secure_c_ses}; __Host-C_OSES={host_c_oses}',
    }

    resp = requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=30)
    # 检查响应状态
    if resp.status_code != 200:
        raise Exception(f"获取xsrfToken失败: {resp.status_code} {resp.text}")
    
    # 处理Google安全前缀
    text = resp.text
    if text.startswith(")]}'\n") or text.startswith(")]}'"): 
        text = text[4:].strip()

    data = json.loads(text)
    key_id = data["keyId"]
    print(f"账号: {account.get('csesidx')} 账号可用! key_id: {key_id}")
    xsrf_token = data["xsrfToken"]

    key_bytes = decode_xsrf_token(xsrf_token)

    return create_jwt(key_bytes, key_id, csesidx)


def get_headers(jwt: str) -> dict:
    """获取请求头"""
    return {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "authorization": f"Bearer {jwt}",
        "content-type": "application/json",
        "origin": "https://business.gemini.google",
        "referer": "https://business.gemini.google/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "x-server-timeout": "1800",
    }


def ensure_jwt_for_account(account_idx: int, account: dict):
    """确保指定账号的JWT有效，必要时刷新"""
    with account_manager.lock:
        state = account_manager.account_states[account_idx]
        if state["jwt"] is None or time.time() - state["jwt_time"] > 240:
            proxy = account_manager.config.get("proxy")
            try:
                state["jwt"] = get_jwt_for_account(account, proxy)
                state["jwt_time"] = time.time()
            except Exception as e:
                # JWT获取失败，标记账号不可用
                account_manager.mark_account_unavailable(account_idx, str(e))
                raise
        return state["jwt"]


def create_chat_session(jwt: str, team_id: str, proxy: str) -> str:
    """创建会话，返回session ID"""
    session_id = uuid.uuid4().hex[:12]
    body = {
        "configId": team_id,
        "additionalParams": {"token": "-"},
        "createSessionRequest": {
            "session": {"name": session_id, "displayName": session_id}
        }
    }

    proxies = {"http": proxy, "https": proxy} if proxy else None
    resp = requests.post(
        CREATE_SESSION_URL,
        headers=get_headers(jwt),
        json=body,
        proxies=proxies,
        verify=False,
        timeout=30
    )

    if resp.status_code != 200:
        if resp.status_code == 401:
            print(f"账号: {account.get('csesidx')} 一般情况下都是team_id填错了～")
        raise Exception(f"创建会话失败: {resp.status_code}")

    data = resp.json()
    return data.get("session", {}).get("name")


def ensure_session_for_account(account_idx: int, account: dict):
    """确保指定账号的会话有效"""
    jwt = ensure_jwt_for_account(account_idx, account)
    with account_manager.lock:
        state = account_manager.account_states[account_idx]
        if state["session"] is None:
            proxy = account_manager.config.get("proxy")
            team_id = account.get("team_id")
            state["session"] = create_chat_session(jwt, team_id, proxy)
        return state["session"], jwt, account.get("team_id")


def stream_chat(jwt: str, sess_name: str, message: str, proxy: str, team_id: str):
    """发送消息并流式接收响应"""
    body = {
        "configId": team_id,
        "additionalParams": {"token": "-"},
        "streamAssistRequest": {
            "session": sess_name,
            "query": {"parts": [{"text": message}]},
            "filter": "",
            "fileIds": [],
            "answerGenerationMode": "NORMAL",
            "toolsSpec": {
                "webGroundingSpec": {},
                "toolRegistry": "default_tool_registry",
                "imageGenerationSpec": {},
                "videoGenerationSpec": {}
            },
            "languageCode": "zh-CN",
            "userMetadata": {"timeZone": "Etc/GMT-8"},
            "assistSkippingMode": "REQUEST_ASSIST"
        }
    }

    proxies = {"http": proxy, "https": proxy} if proxy else None
    resp = requests.post(
        STREAM_ASSIST_URL,
        headers=get_headers(jwt),
        json=body,
        proxies=proxies,
        verify=False,
        timeout=120,
        stream=True
    )

    if resp.status_code != 200:
        raise Exception(f"请求失败: {resp.status_code}")

    # 收集完整响应
    full_response = ""
    for line in resp.iter_lines():
        if line:
            full_response += line.decode('utf-8') + "\n"

    # 解析响应
    result_text = ""
    try:
        data_list = json.loads(full_response)
        for data in data_list:
            if "streamAssistResponse" in data:
                sar = data["streamAssistResponse"]
                if "answer" in sar:
                    answer = sar["answer"]
                    if "replies" in answer:
                        for reply in answer["replies"]:
                            gc = reply.get("groundedContent", {})
                            content = gc.get("content", {})
                            text = content.get("text", "")
                            thought = content.get("thought", False)
                            if text and not thought:
                                result_text += text
    except json.JSONDecodeError:
        pass

    return result_text


# ==================== OpenAPI 接口 ====================

@app.route('/v1/models', methods=['GET'])
def list_models():
    """获取模型列表"""
    models_config = account_manager.config.get("models", [])
    models_data = []
    
    for model in models_config:
        models_data.append({
            "id": model.get("id", "gemini-enterprise"),
            "object": "model",
            "created": int(time.time()),
            "owned_by": "google",
            "permission": [],
            "root": model.get("id", "gemini-enterprise"),
            "parent": None
        })
    
    # 如果没有配置模型，返回默认模型
    if not models_data:
        models_data.append({
            "id": "gemini-enterprise",
            "object": "model",
            "created": int(time.time()),
            "owned_by": "google",
            "permission": [],
            "root": "gemini-enterprise",
            "parent": None
        })
    
    return jsonify({"object": "list", "data": models_data})


@app.route('/v1/chat/completions', methods=['POST'])
def chat_completions():
    """聊天对话接口"""
    try:
        data = request.json
        messages = data.get('messages', [])
        stream = data.get('stream', False)

        # 提取用户消息
        user_message = ""
        for msg in messages:
            if msg.get('role') == 'user':
                content = msg.get('content', '')
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get('type') == 'text':
                            user_message = item.get('text', '')
                            break
                else:
                    user_message = content

        if not user_message:
            return jsonify({"error": "No user message found"}), 400
        
        # 轮训获取账号
        max_retries = len(account_manager.accounts)
        last_error = None
        
        for _ in range(max_retries):
            try:
                account_idx, account = account_manager.get_next_account()
                csesidx = account.get("csesidx", "unknown")
                print(f"[调度] 当前使用账号CSESIDX: {csesidx}")
                session, jwt, team_id = ensure_session_for_account(account_idx, account)
                proxy = account_manager.config.get("proxy")
                
                # 发送请求
                response_text = stream_chat(jwt, session, user_message, proxy, team_id)
                break
            except Exception as e:
                last_error = e
                continue
        else:
            # 所有账号都失败
            return jsonify({"error": f"所有账号请求失败: {last_error}"}), 500

        if stream:
            # 流式响应
            def generate():
                chunk_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
                chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": "gemini-enterprise",
                    "choices": [{
                        "index": 0,
                        "delta": {"content": response_text},
                        "finish_reason": None
                    }]
                }
                yield f"data: {json.dumps(chunk)}\n\n"
                
                # 结束标记
                end_chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": "gemini-enterprise",
                    "choices": [{
                        "index": 0,
                        "delta": {},
                        "finish_reason": "stop"
                    }]
                }
                yield f"data: {json.dumps(end_chunk)}\n\n"
                yield "data: [DONE]\n\n"

            return Response(generate(), mimetype='text/event-stream')
        else:
            # 非流式响应
            response = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": "gemini-enterprise",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": response_text
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": len(user_message),
                    "completion_tokens": len(response_text),
                    "total_tokens": len(user_message) + len(response_text)
                }
            }
            return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route('/api/status', methods=['GET'])
def system_status():
    """获取系统状态"""
    total, available = account_manager.get_account_count()
    proxy = account_manager.config.get("proxy")
    
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "accounts": {
            "total": total,
            "available": available
        },
        "proxy": {
            "url": proxy,
            "available": check_proxy(proxy) if proxy else False
        },
        "models": account_manager.config.get("models", [])
    })


# ==================== 管理接口 ====================

@app.route('/')
@app.route('/index.html')
def index():
    """返回管理页面"""
    return send_from_directory('.', 'index.html')

@app.route('/chat_history.html')
def chat_history():
    """返回聊天记录页面"""
    return send_from_directory('.', 'chat_history.html')

@app.route('/api/accounts', methods=['GET'])
def get_accounts():
    """获取账号列表"""
    accounts_data = []
    for i, acc in enumerate(account_manager.accounts):
        state = account_manager.account_states.get(i, {})
        # 返回完整值用于编辑，前端显示时再截断
        accounts_data.append({
            "id": i,
            "team_id": acc.get("team_id", ""),
            "secure_c_ses": acc.get("secure_c_ses", ""),
            "host_c_oses": acc.get("host_c_oses", ""),
            "csesidx": acc.get("csesidx", ""),
            "user_agent": acc.get("user_agent", ""),
            "available": state.get("available", True),
            "unavailable_reason": acc.get("unavailable_reason", ""),
            "has_jwt": state.get("jwt") is not None
        })
    return jsonify({"accounts": accounts_data})


@app.route('/api/accounts', methods=['POST'])
def add_account():
    """添加账号"""
    data = request.json
    new_account = {
        "team_id": data.get("team_id", ""),
        "secure_c_ses": data.get("secure_c_ses", ""),
        "host_c_oses": data.get("host_c_oses", ""),
        "csesidx": data.get("csesidx", ""),
        "user_agent": data.get("user_agent", "Mozilla/5.0"),
        "available": True
    }
    
    account_manager.accounts.append(new_account)
    idx = len(account_manager.accounts) - 1
    account_manager.account_states[idx] = {
        "jwt": None,
        "jwt_time": 0,
        "session": None,
        "available": True
    }
    account_manager.config["accounts"] = account_manager.accounts
    account_manager.save_config()
    
    return jsonify({"success": True, "id": idx})


@app.route('/api/accounts/<int:account_id>', methods=['PUT'])
def update_account(account_id):
    """更新账号"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    data = request.json
    acc = account_manager.accounts[account_id]
    
    if "team_id" in data:
        acc["team_id"] = data["team_id"]
    if "secure_c_ses" in data:
        acc["secure_c_ses"] = data["secure_c_ses"]
    if "host_c_oses" in data:
        acc["host_c_oses"] = data["host_c_oses"]
    if "csesidx" in data:
        acc["csesidx"] = data["csesidx"]
    if "user_agent" in data:
        acc["user_agent"] = data["user_agent"]
    
    # 同步更新config中的accounts
    account_manager.config["accounts"] = account_manager.accounts
    account_manager.save_config()
    return jsonify({"success": True})


@app.route('/api/accounts/<int:account_id>', methods=['DELETE'])
def delete_account(account_id):
    """删除账号"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    account_manager.accounts.pop(account_id)
    # 重建状态映射
    new_states = {}
    for i in range(len(account_manager.accounts)):
        if i < account_id:
            new_states[i] = account_manager.account_states.get(i, {})
        else:
            new_states[i] = account_manager.account_states.get(i + 1, {})
    account_manager.account_states = new_states
    account_manager.config["accounts"] = account_manager.accounts
    account_manager.save_config()
    
    return jsonify({"success": True})


@app.route('/api/accounts/<int:account_id>/toggle', methods=['POST'])
def toggle_account(account_id):
    """切换账号状态"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    state = account_manager.account_states.get(account_id, {})
    current = state.get("available", True)
    state["available"] = not current
    account_manager.accounts[account_id]["available"] = not current
    
    if not current:
        # 重新启用时清除错误信息
        account_manager.accounts[account_id].pop("unavailable_reason", None)
        account_manager.accounts[account_id].pop("unavailable_time", None)
    
    account_manager.save_config()
    return jsonify({"success": True, "available": not current})


@app.route('/api/accounts/<int:account_id>/test', methods=['GET'])
def test_account(account_id):
    """测试账号JWT获取"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    account = account_manager.accounts[account_id]
    proxy = account_manager.config.get("proxy")
    
    try:
        jwt = get_jwt_for_account(account, proxy)
        return jsonify({"success": True, "message": "JWT获取成功"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route('/api/models', methods=['GET'])
def get_models_config():
    """获取模型配置"""
    models = account_manager.config.get("models", [])
    return jsonify({"models": models})


@app.route('/api/models', methods=['POST'])
def add_model():
    """添加模型"""
    data = request.json
    new_model = {
        "id": data.get("id", ""),
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "context_length": data.get("context_length", 32768),
        "max_tokens": data.get("max_tokens", 8192),
        "enabled": data.get("enabled", True)
    }
    
    if "models" not in account_manager.config:
        account_manager.config["models"] = []
    
    account_manager.config["models"].append(new_model)
    account_manager.save_config()
    
    return jsonify({"success": True})


@app.route('/api/models/<model_id>', methods=['PUT'])
def update_model(model_id):
    """更新模型"""
    models = account_manager.config.get("models", [])
    for model in models:
        if model.get("id") == model_id:
            data = request.json
            if "name" in data:
                model["name"] = data["name"]
            if "description" in data:
                model["description"] = data["description"]
            if "context_length" in data:
                model["context_length"] = data["context_length"]
            if "max_tokens" in data:
                model["max_tokens"] = data["max_tokens"]
            if "enabled" in data:
                model["enabled"] = data["enabled"]
            account_manager.save_config()
            return jsonify({"success": True})
    
    return jsonify({"error": "模型不存在"}), 404


@app.route('/api/models/<model_id>', methods=['DELETE'])
def delete_model(model_id):
    """删除模型"""
    models = account_manager.config.get("models", [])
    for i, model in enumerate(models):
        if model.get("id") == model_id:
            models.pop(i)
            account_manager.save_config()
            return jsonify({"success": True})
    
    return jsonify({"error": "模型不存在"}), 404


@app.route('/api/config', methods=['GET'])
def get_config():
    """获取完整配置"""
    return jsonify(account_manager.config)


@app.route('/api/config', methods=['PUT'])
def update_config():
    """更新配置"""
    data = request.json
    if "proxy" in data:
        account_manager.config["proxy"] = data["proxy"]
    account_manager.save_config()
    return jsonify({"success": True})


@app.route('/api/config/import', methods=['POST'])
def import_config():
    """导入配置"""
    try:
        data = request.json
        account_manager.config = data
        account_manager.accounts = data.get("accounts", [])
        # 重建账号状态
        account_manager.account_states = {}
        for i, acc in enumerate(account_manager.accounts):
            available = acc.get("available", True)
            account_manager.account_states[i] = {
                "jwt": None,
                "jwt_time": 0,
                "session": None,
                "available": available
            }
        account_manager.save_config()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/proxy/test', methods=['POST'])
def test_proxy():
    """测试代理"""
    data = request.json
    proxy_url = data.get("proxy") or account_manager.config.get("proxy")
    
    if not proxy_url:
        return jsonify({"success": False, "message": "未配置代理地址"})
    
    available = check_proxy(proxy_url)
    return jsonify({
        "success": available,
        "message": "代理可用" if available else "代理不可用或连接超时"
    })


@app.route('/api/proxy/status', methods=['GET'])
def get_proxy_status():
    """获取代理状态"""
    proxy = account_manager.config.get("proxy")
    if not proxy:
        return jsonify({"enabled": False, "url": None, "available": False})
    
    available = check_proxy(proxy)
    return jsonify({
        "enabled": True,
        "url": proxy,
        "available": available
    })


@app.route('/api/config/export', methods=['GET'])
def export_config():
    """导出配置"""
    return jsonify(account_manager.config)


def print_startup_info():
    """打印启动信息"""
    print("="*60)
    print("Business Gemini OpenAPI 服务 (多账号轮训版)")
    print("="*60)
    
    # 加载配置
    account_manager.load_config()
    
    # 代理信息
    proxy = account_manager.config.get("proxy")
    print(f"\n[代理配置]")
    print(f"  地址: {proxy or '未配置'}")
    if proxy:
        proxy_available = check_proxy(proxy)
        print(f"  状态: {'✓ 可用' if proxy_available else '✗ 不可用'}")
    
    # 账号信息
    total, available = account_manager.get_account_count()
    print(f"\n[账号配置]")
    print(f"  总数量: {total}")
    print(f"  可用数量: {available}")
    
    for i, acc in enumerate(account_manager.accounts):
        status = "✓" if account_manager.account_states.get(i, {}).get("available", True) else "✗"
        team_id = acc.get("team_id", "未知") + "..."
        print(f"  [{i}] {status} team_id: {team_id}")
    
    # 模型信息
    models = account_manager.config.get("models", [])
    print(f"\n[模型配置]")
    if models:
        for model in models:
            print(f"  - {model.get('id')}: {model.get('name', '')}")
    else:
        print("  - gemini-enterprise (默认)")
    
    print(f"\n[接口列表]")
    print("  GET  /v1/models           - 获取模型列表")
    print("  POST /v1/chat/completions - 聊天对话")
    print("  GET  /v1/status           - 系统状态")
    print("  GET  /health              - 健康检查")
    print("\n" + "="*60)
    print("启动服务...")


def run():
    print_startup_info()
    
    if not account_manager.accounts:
        print("[!] 警告: 没有配置任何账号")
    
    host = os.getenv("HOST", os.getenv("FLASK_RUN_HOST", "0.0.0.0"))
    port = int(os.getenv("PORT", os.getenv("FLASK_RUN_PORT", "8000")))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run()
