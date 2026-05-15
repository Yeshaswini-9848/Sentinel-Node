import os
import sys
import time

from flask import Flask, jsonify, render_template, request

# Ensure packet_sniffer is importable from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from packet_sniffer import NetworkSniffer

app = Flask(__name__)
sniffer = NetworkSniffer()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── API: Control ──────────────────────────────────────────────────────────────

@app.route("/api/start_monitoring", methods=["POST"])
def start_monitoring():
    if sniffer.is_monitoring:
        return jsonify({"status": "error", "message": "Monitoring already active."})

    data = request.get_json(silent=True) or {}
    simulate = data.get("simulate", False)
    interface = data.get("interface") or None

    sniffer.interface = interface
    sniffer.start_monitoring(simulation_mode=simulate)

    return jsonify({
        "status": "success",
        "message": "Monitoring started.",
        "simulation": simulate,
    })


@app.route("/api/stop_monitoring", methods=["POST"])
def stop_monitoring():
    if not sniffer.is_monitoring:
        return jsonify({"status": "error", "message": "No active monitoring session."})

    sniffer.stop_monitoring()
    return jsonify({"status": "success", "message": "Monitoring stopped."})


# ── API: Data ─────────────────────────────────────────────────────────────────

@app.route("/api/traffic_data")
def traffic_data():
    """Return the last N enriched packet records plus aggregate stats."""
    traffic = sniffer.get_latest_traffic()
    stats = sniffer.get_stats()

    return jsonify({
        "status": "success",
        "traffic": traffic[-50:],   # most recent 50 packets to the dashboard
        "stats": stats,
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    })


@app.route("/api/status")
def status():
    """Lightweight heartbeat / status endpoint."""
    return jsonify({
        "monitoring": sniffer.is_monitoring,
        "simulation": sniffer.simulation_mode,
        "packet_count": len(sniffer.packet_queue),
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(os.path.join("..", "logs"), exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
