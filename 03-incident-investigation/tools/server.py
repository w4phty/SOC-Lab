from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["POST"])
def upload():
    data = request.get_data()
    print(f"Received {len(data)} bytes")
    return "Success\n"

app.run(host="0.0.0.0", port=443)