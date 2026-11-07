from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/hello")
def hello():
    return jsonify(message="hello")
