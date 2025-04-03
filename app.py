from flask import Flask, render_template, request, jsonify
from safe_browsing_test import check_url_with_safe_browsing
import os

app = Flask(__name__)

# Set your Google Safe Browsing API key here or use an environment variable
API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY") or "AIzaSyBdn7VEo1HR8RiIQmJSvcZeU_YXIxQxINA"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check_url", methods=["POST"])
def check_url():
    url = request.form.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Call the function from safe_browsing_test.py
    result = check_url_with_safe_browsing(API_KEY, url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)