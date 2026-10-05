import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
CORS(app)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///cybersentinel.db"
)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class SecurityLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    event_type = db.Column(
        db.String(100),
        nullable=False
    )

    source_ip = db.Column(
        db.String(45),
        nullable=False
    )

    username = db.Column(
        db.String(100)
    )

    status = db.Column(
        db.String(50),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="LOW"
    )

    message = db.Column(
        db.String(255)
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self):

        return {
            "id": self.id,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "username": self.username,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "created_at":
                self.created_at.isoformat()
                if self.created_at
                else None
        }


# ==============================
# THREAT DETECTION ENGINE
# ==============================

def detect_threat(data):

    event_type = str(
        data.get("event_type", "")
    ).upper()

    status = str(
        data.get("status", "")
    ).upper()

    message = str(
        data.get("message", "")
    ).lower()


    if event_type == "BRUTE_FORCE":

        return (
            "HIGH",
            "Brute-force attack pattern detected"
        )


    if event_type == "SUSPICIOUS_LOGIN":

        return (
            "HIGH",
            "Suspicious login activity detected"
        )


    if event_type == "MALWARE_ALERT":

        return (
            "CRITICAL",
            "Malware-related security event detected"
        )


    if (
        event_type == "LOGIN_FAILURE"
        and status == "FAILED"
    ):

        return (
            "MEDIUM",
            "Failed login attempt detected"
        )


    suspicious_words = [
        "attack",
        "exploit",
        "unauthorized",
        "intrusion",
        "malware"
    ]


    for word in suspicious_words:

        if word in message:

            return (
                "HIGH",
                f"Suspicious activity detected: {word}"
            )


    return (
        "LOW",
        "No significant threat detected"
    )


# ==============================
# CREATE DATABASE
# ==============================

with app.app_context():

    db.create_all()


# ==============================
# HOME
# ==============================

@app.route("/")
def home():

    return jsonify({

        "project":
            "CyberSentinel",

        "version":
            "1.0",

        "status":
            "online",

        "service":
            "Cybersecurity Threat Detection and SOC Monitoring API"
    })


# ==============================
# HEALTH CHECK
# ==============================

@app.route("/api/health")
def health():

    return jsonify({

        "status":
            "healthy",

        "database":
            "connected",

        "security_engine":
            "active"
    })


# ==============================
# CREATE SECURITY LOG
# ==============================

@app.route(
    "/api/logs",
    methods=["POST"]
)
def create_log():

    data = request.get_json(
        silent=True
    ) or {}


    required_fields = [
        "event_type",
        "source_ip",
        "status"
    ]


    for field in required_fields:

        if not data.get(field):

            return jsonify({

                "error":
                    f"Missing field: {field}"

            }), 400


    severity, analysis = detect_threat(
        data
    )


    log = SecurityLog(

        event_type=data[
            "event_type"
        ],

        source_ip=data[
            "source_ip"
        ],

        username=data.get(
            "username"
        ),

        status=data[
            "status"
        ],

        severity=severity,

        message=analysis
    )


    db.session.add(log)

    db.session.commit()


    return jsonify({

        "message":
            "Security event analyzed successfully",

        "threat_detection": {

            "severity":
                severity,

            "analysis":
                analysis
        },

        "log":
            log.to_dict()

    }), 201


# ==============================
# GET SECURITY LOGS
# ==============================

@app.route(
    "/api/logs",
    methods=["GET"]
)
def get_logs():

    logs = SecurityLog.query.order_by(
        SecurityLog.id.desc()
    ).limit(100).all()


    return jsonify({

        "count":
            len(logs),

        "logs":
            [
                log.to_dict()
                for log in logs
            ]
    })


# ==============================
# SECURITY SUMMARY
# ==============================

@app.route(
    "/api/security-summary"
)
def security_summary():

    logs = SecurityLog.query.all()


    counts = {

        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }


    for log in logs:

        if log.severity in counts:

            counts[
                log.severity
            ] += 1


    if counts["CRITICAL"] > 0:

        risk = "CRITICAL RISK"

    elif counts["HIGH"] > 0:

        risk = "HIGH RISK"

    elif counts["MEDIUM"] > 0:

        risk = "MEDIUM RISK"

    else:

        risk = "NORMAL"


    return jsonify({

        "total_events":
            len(logs),

        "low":
            counts["LOW"],

        "medium":
            counts["MEDIUM"],

        "high":
            counts["HIGH"],

        "critical":
            counts["CRITICAL"],

        "security_status":
            risk
    })


# ==============================
# START SERVER
# ==============================

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )

    app.run(

        host="0.0.0.0",

        port=port,

        debug=False
    )