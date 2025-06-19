from flask import Flask, render_template, request
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

app = Flask(__name__)

# Tạo khóa RSA sẵn (tạm thời dùng 1 lần)
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

@app.route("/", methods=["GET", "POST"])
def index():
    message = None

    if request.method == "POST":
        file = request.files["file"]
        if file:
            data = file.read()

            # Ký file
            hash_obj = SHA256.new(data)
            signature = pkcs1_15.new(private_key).sign(hash_obj)

            # Xác minh lại
            try:
                pkcs1_15.new(public_key).verify(hash_obj, signature)
                message = "✅ Chữ ký hợp lệ. File được ký và xác minh thành công!"
            except (ValueError, TypeError):
                message = "❌ Chữ ký không hợp lệ."

    return render_template("index.html", message=message)
