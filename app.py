import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request, redirect, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth

# =========================================================
# APP CONFIGURATION
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# =========================================================
# DATABASE
# =========================================================

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

db = SQLAlchemy(app)

# =========================================================
# CORS
# =========================================================

CORS(
    app,
    supports_credentials=True,
    origins=[
        "https://cyber-sentinel-navy.vercel.app"
    ]
)

# =========================================================
# GOOGLE OAUTH
# =========================================================

oauth = OAuth(app)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://cybersentinel-qcl5.onrender.com/api/auth/google/callback"
)

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:

    oauth.register(
        name="google",

        client_id=GOOGLE_CLIENT_ID,

        client_secret=GOOGLE_CLIENT_SECRET,

        server_metadata_url=(
            "https://accounts.google.com/"
            ".well-known/openid-configuration"
        ),

        client_kwargs={
            "scope": "openid email profile"
        }
    )

# =========================================================
# SECURITY LOG MODEL
# =========================================================

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


# =========================================================
# THREAT DETECTION ENGINE
# =========================================================

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


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

with app.app_context():

    db.create_all()


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return jsonify({

        "project":
            "CyberSentinel",

        "version":
            "2.0",

        "status":
            "online",

        "service":
            "Cybersecurity Threat Detection and SOC Monitoring API",

        "authentication":
            "Google OAuth 2.0",

        "database":
            "PostgreSQL"
            if DATABASE_URL.startswith("postgresql")
            else "SQLite"
    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health")
def health():

    try:

        db.session.execute(
            db.text("SELECT 1")
        )

        database_status = "connected"

    except Exception:

        database_status = "error"

    return jsonify({

        "status":
            "healthy",

        "database":
            database_status,

        "security_engine":
            "active",

        "google_auth":
            "configured"
            if GOOGLE_CLIENT_ID
            and GOOGLE_CLIENT_SECRET
            else "not_configured"
    })


# =========================================================
# GOOGLE LOGIN
# =========================================================

@app.route("/api/auth/google")
def google_login():

    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:

        return jsonify({

            "error":
                "Google OAuth is not configured"
        }), 500

    redirect_uri = GOOGLE_REDIRECT_URI

    return oauth.google.authorize_redirect(
        redirect_uri
    )


# =========================================================
# GOOGLE CALLBACK
# =========================================================

@app.route("/api/auth/google/callback")
def google_callback():

    try:

        token = oauth.google.authorize_access_token()

        user_info = token.get("userinfo")

        if not user_info:

            user_info = oauth.google.userinfo()

        session["user"] = {

            "id":
                user_info.get("sub"),

            "name":
                user_info.get("name"),

            "email":
                user_info.get("email"),

            "picture":
                user_info.get("picture")
        }

        # Redirect user back to Vercel frontend
        return redirect(
            "https://cyber-sentinel-navy.vercel.app/"
        )

    except Exception as error:

        return jsonify({

            "error":
                "Google authentication failed",

            "details":
                str(error)
        }), 500


# =========================================================
# CURRENT USER
# =========================================================

@app.route("/api/auth/me")
def current_user():

    user = session.get("user")

    if not user:

        return jsonify({

            "authenticated":
                False
        })

    return jsonify({

        "authenticated":
            True,

        "user":
            user
    })


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/api/auth/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return jsonify({

        "message":
            "Logged out successfully"
    })


# =========================================================
# CREATE SECURITY LOG
# =========================================================

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


# =========================================================
# GET SECURITY LOGS
# =========================================================

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


# =========================================================
# SECURITY SUMMARY
# =========================================================

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


# =========================================================
# START SERVER
# =========================================================

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
