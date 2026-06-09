from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib, base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dh_web_secret'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

print("[*] Generating DH parameters (2048-bit)...")
_dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
print("[*] DH parameters ready.")

sessions = {}


def derive_aes_key(shared_secret_bytes):
    return hashlib.sha256(shared_secret_bytes).digest()


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
    return render_template('index_dh_aes.html')


@socketio.on('connect')
def on_connect():
    sid = request.sid
    private_key = _dh_parameters.generate_private_key()
    public_key  = private_key.public_key()

    pn = _dh_parameters.parameter_numbers()
    pub_numbers = public_key.public_numbers()


    sessions[sid] = {
        'server_private': private_key,
        'aes_key': None,
        'username': None
    }

    emit('dh_params', {
        'p': str(pn.p),
        'g': str(pn.g),
        'server_y': str(pub_numbers.y)
    })
    print(f"[+] {sid[:8]} connected, DH params sent")


@socketio.on('disconnect')
def on_disconnect():
    info = sessions.pop(request.sid, {})
    name = info.get('username', '')
    if name:
        emit('system_msg', {'text': f'[{name} left the chat]'}, broadcast=True)
    print(f"[-] {name} disconnected")


@socketio.on('client_public_key')
def on_client_public_key(data):
    sid = request.sid
    sess = sessions.get(sid)
    if not sess:
        emit('error_msg', {'text': 'Invalid session'}); return

    username = data.get('username', f'User_{sid[:4]}')
    try:
        client_y = int(data['client_y'])

        pn = _dh_parameters.parameter_numbers()
        shared_int = pow(client_y, sess['server_private'].private_numbers().x, pn.p)
        shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, 'big')
        aes_key = derive_aes_key(shared_bytes)

        sess['aes_key']  = aes_key
        sess['username'] = username
        print(f"[DH] {username}: shared={shared_bytes.hex()[:16]}...")

        emit('dh_success', {
            'shared_preview': shared_bytes.hex()[:24] + '...',
            'aes_key_preview': aes_key.hex()[:16] + '...'
        })
        emit('system_msg', {'text': f'[{username} joined the chat]'}, broadcast=True)

    except Exception as e:
        emit('error_msg', {'text': str(e)}); print(f"[ERR] {e}")


@socketio.on('chat_message')
def on_chat_message(data):
    sid = request.sid
    sess = sessions.get(sid)
    if not sess or not sess['aes_key']:
        emit('error_msg', {'text': 'Not connected securely'}); return
    try:
        plain = decrypt_message(sess['aes_key'], base64.b64decode(data['encrypted_msg']))
        username = sess['username']
        print(f"[MSG] {username}: {plain}")

        for other_sid, other_sess in sessions.items():
            if other_sid != sid and other_sess.get('aes_key'):
                enc = encrypt_message(other_sess['aes_key'], f"{username}: {plain}")
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
        emit('error_msg', {'text': str(e)}); print(f"[ERR] {e}")


if __name__ == '__main__':
    print("DH-AES Secure Chat -> http://127.0.0.1:5002")
    socketio.run(app, host='0.0.0.0', port=5002, debug=False,
                 allow_unsafe_werkzeug=True)