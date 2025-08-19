from flask import Flask, request
from ..services.packet_ingestor import PacketIngestor
from ..services.threat_intel import ThreatIntelService
from ..detector.anomaly_detector import AnomalyDetector


packet_ingestor = PacketIngestor()
threat_intel = ThreatIntelService()
detector = AnomalyDetector()

def register_routes(app: Flask) -> None:
    @app.post("/api/ingest")
    def ingest():
        payload = request.get_json(force=True, silent=True) or {}
        packet = payload.get("packet", {})
        packet_ingestor.ingest(packet)
        return {"ingested": True}

    @app.get("/api/incidents")
    def incidents():
        return {"incidents": packet_ingestor.get_incidents()}

    @app.post("/api/scan")
    def scan():
        target_ip = (request.get_json() or {}).get("ip")
        if not target_ip:
            return {"error": "ip required"}, 400
        result = threat_intel.port_scan(target_ip)
        return {"scan": result}

    @app.post("/api/analyze")
    def analyze():
        payload = request.get_json(force=True, silent=True) or {}
        packet = payload.get("packet", {})
        score = detector.score(packet)
        decision = score > 0.8
        return {"score": score, "suspicious": decision}