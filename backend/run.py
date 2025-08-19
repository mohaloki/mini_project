import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from backend.services.packet_ingestor import PacketIngestor
from backend.services.threat_intel import ThreatIntelService
from backend.detector.anomaly_detector import AnomalyDetector
from backend.services.geoip import GeoIPService
from backend.services.firewall import FirewallService


packet_ingestor = PacketIngestor()
threat_intel = ThreatIntelService()
detector = AnomalyDetector()
geoip = GeoIPService()
firewall = FirewallService(dry_run=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "NetGuardPro/0.1"

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return
        if path == "/api/incidents":
            self._set_headers(200)
            self.wfile.write(json.dumps({"incidents": packet_ingestor.get_incidents()}).encode())
            return
        if path == "/api/reputation":
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = {}
            for pair in query.split("&"):
                if not pair:
                    continue
                k, _, v = pair.partition("=")
                params[k] = v
            ip = params.get("ip")
            if not ip:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "ip required"}).encode())
                return
            rep = threat_intel.reputation(ip)
            rep["geo_feed"] = rep.get("geo")
            rep["geo_db"] = geoip.country_for_ip(ip)
            self._set_headers(200)
            self.wfile.write(json.dumps(rep).encode())
            return
        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "not found"}).encode())

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        try:
            data = self.rfile.read(length)
            return json.loads(data.decode() or "{}")
        except Exception:
            return {}

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_json()

        if path == "/api/ingest":
            packet = body.get("packet", {})
            packet_ingestor.ingest(packet)
            self._set_headers(200)
            self.wfile.write(json.dumps({"ingested": True}).encode())
            return

        if path == "/api/scan":
            ip = (body or {}).get("ip")
            if not ip:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "ip required"}).encode())
                return
            result = threat_intel.port_scan(ip)
            self._set_headers(200)
            self.wfile.write(json.dumps({"scan": result}).encode())
            return

        if path == "/api/block_ip":
            ip = (body or {}).get("ip")
            reason = (body or {}).get("reason")
            res = firewall.block_ip(ip, reason)
            status = 200 if not res.get("error") else 400
            self._set_headers(status)
            self.wfile.write(json.dumps(res).encode())
            return

        if path == "/api/analyze":
            packet = body.get("packet", {})
            autoblock = bool(body.get("autoblock", False))
            score = detector.score(packet)
            decision = score > 0.8
            response = {"score": score, "suspicious": decision}
            if decision and autoblock:
                ip = packet.get("src_ip") or packet.get("dst_ip")
                if ip:
                    response["action"] = firewall.block_ip(ip, reason="autoblock")
            self._set_headers(200)
            self.wfile.write(json.dumps(response).encode())
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "not found"}).encode())


def run(host: str = "0.0.0.0", port: int = 8000):
    httpd = HTTPServer((host, port), Handler)
    print(f"NetGuard Pro stdlib API listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run()