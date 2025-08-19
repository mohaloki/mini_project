from flask import Flask
from flask_cors import CORS
from .routes import register_routes


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)

    register_routes(app)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8000)