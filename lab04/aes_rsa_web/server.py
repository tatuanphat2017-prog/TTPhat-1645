from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'aes_rsa_web_secret'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# Server RSA key pair - dung de nhan AES key tu client
server_key = RSA.generate(2048)

# sid -> { aes_key, username }
clients = {}


def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ct


def decrypt_message(key, data):
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


@app.route('/')
def index():
    return render_template('index_aes_rsa.html')


@socketio.on('connect')
def on_connect():
    # Gui RSA public key cho client
    pub_pem = server_key.publickey().export_key('PEM').decode()
    emit('server_public_key', {'public_key': pub_pem})
    print(f"[+] {request.sid[:8]} connected, RSA public key sent")


@socketio.on('disconnect')
def on_disconnect():
    info = clients.pop(request.sid, {})
    name = info.get('username', '')
    if name:
        emit('system_msg', {'text': f'[{name} left the chat]'}, broadcast=True)
    print(f"[-] {name} disconnected")


@socketio.on('client_aes_key')
def on_client_aes_key(data):
    """
    Client gui AES key da ma hoa bang RSA public key cua server.
    Server dung RSA private key de giai ma -> lay AES key.
    """
    sid = request.sid
    username = data.get('username', f'User_{sid[:4]}')
    try:
        enc_b64 = data['encrypted_aes_key']
        enc_bytes = base64.b64decode(enc_b64)

        # Giai ma bang PKCS1_v1_5 (JSEncrypt dung v1_5)
        cipher_rsa = PKCS1_v1_5.new(server_key)
        sentinel = b'FAIL'
        decrypted = cipher_rsa.decrypt(enc_bytes, sentinel)

        if decrypted == sentinel:
            emit('error_msg', {'text': 'RSA decrypt failed'}); return

        # Client gui hex string -> chuyen lai thanh bytes
        try:
            aes_key = bytes.fromhex(decrypted.decode())
        except Exception:
            aes_key = decrypted  # fallback: dung thang

        if len(aes_key) != 16:
            emit('error_msg', {'text': f'AES key invalid len={len(aes_key)}'}); return

        clients[sid] = {'aes_key': aes_key, 'username': username}
        print(f"[KEY] {username}: AES key OK, len={len(aes_key)}")

        emit('key_received_ok', {'msg': 'AES key received'})
        emit('system_msg', {'text': f'[{username} joined the chat]'}, broadcast=True)

    except Exception as e:
        emit('error_msg', {'text': str(e)})
        print(f"[ERR] {e}")


@socketio.on('chat_message')
def on_chat_message(data):
    sid = request.sid
    info = clients.get(sid)
    if not info:
        return
    try:
        enc_bytes = base64.b64decode(data['encrypted_msg'])
        plain = decrypt_message(info['aes_key'], enc_bytes)
        username = info['username']
        print(f"[MSG] {username}: {plain}")

        for other_sid, other_info in clients.items():
            if other_sid != sid:
                enc = encrypt_message(other_info['aes_key'], f"{username}: {plain}")
                socketio.emit('chat_message', {
                    'from': username, 'plain': plain,
                    'enc_preview': base64.b64encode(enc).decode()[:40] + '...',
                    'is_mine': False
                }, to=other_sid)

        emit('chat_message', {
            'from': username, 'plain': plain,
            'enc_preview': data['encrypted_msg'][:40] + '...',
            'is_mine': True
        })
    except Exception as e:
        emit('error_msg', {'text': str(e)})
        print(f"[ERR] decrypt: {e}")


if __name__ == '__main__':
    print("AES-RSA Secure Chat -> http://127.0.0.1:5001")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True,
                 allow_unsafe_werkzeug=True)