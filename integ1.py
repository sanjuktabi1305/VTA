from flask import Flask, request, jsonify, render_template
app = Flask(__name__, template_folder="templates")

# assume you already have scan_code(code) implemented and returning a list of findings
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error":"no file uploaded"}), 400
    uploaded = request.files["file"]
    code = uploaded.read().decode("utf-8", errors="replace")
    findings = scan_code(code)            # your scanner function that returns list/dicts
    return jsonify({"findings": findings})

