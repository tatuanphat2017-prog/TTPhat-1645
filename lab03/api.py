from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/caesar/encrypt', methods=['POST'])
def caesar_encrypt():
    data = request.json
    plain_text = data.get('plain_text', '')
    key = int(data.get('key', 0))
    encrypted = ''.join(chr((ord(c) - 65 + key) % 26 + 65) if c.isalpha() else c for c in plain_text.upper())
    return jsonify({'encrypted_text': encrypted})

@app.route('/api/caesar/decrypt', methods=['POST'])
def caesar_decrypt():
    data = request.json
    cipher_text = data.get('cipher_text', '')
    key = int(data.get('key', 0))
    decrypted = ''.join(chr((ord(c) - 65 - key) % 26 + 65) if c.isalpha() else c for c in cipher_text.upper())
    return jsonify({'decrypted_text': decrypted})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)