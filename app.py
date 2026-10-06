from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime
import os
import requests
import re

# ============================================================
# CYBERSENTINEL - AI CYBER THREAT DETECTION & SOC DASHBOARD
# ============================================================

app = Flask(__name__)

# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    "CyberSentinel-Development-Key"
)

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql+psycopg2://"
    ).replace(
        "postgresql://",
        "postgresql+psycopg2://"
    )

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "https://cyber-sentinel-navy.vercel.app",
                "http://localhost:3000",
                "http://127.0.0.1:3000"
            ]
        }
    },
    supports_credentials=True
)

# ------------------------------------------------------------
# ENVIRONMENT VARIABLES
# ------------------------------------------------------------

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI")

FRONTEND_URL = os.environ.get(
    "FRONTEND_URL",
    "https://cyber-sentinel-navy.vercel.app"
)

# ------------------------------------------------------------
# SIGNED TOKEN SERIALIZER
# ------------------------------------------------------------

serializer = URLSafeTimedSerializer(
    app.config["SECRET_KEY"]
)

# ------------------------------------------------------------
# DATABASE MODEL
# ------------------------------------------------------------

class SecurityLog(db.Model):

    __tablename__ = "security_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    event_type = db.Column(
        db.String(100),
        nullable=False
    )

    source_ip = db.Column(
        db.String(100)
    )

    username = db.Column(
        db.String(150)
    )

    status = db.Column(
        db.String(100)
    )

    severity = db.Column(
        db.String(50)
    )

    message = db.Column(
        db.Text
    )

    # Timestamp
    # Python creates the timestamp when the event is inserted.
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )


# ------------------------------------------------------------
# CREATE DATABASE TABLES
# ------------------------------------------------------------

with app.app_context():

    try:
        db.create_all()
        print("Database tables initialized successfully.")

    except Exception as error:
        print("Database initialization error:", error)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_bearer_token():

    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None

    if not auth_header.startswith("Bearer "):
        return None

    return auth_header.split(
        " ",
        1
    )[1]


def create_auth_token(user_data):

    return serializer.dumps(
        user_data,
        salt="auth-token"
    )


def verify_auth_token(token):

    try:

        data = serializer.loads(
            token,
            salt="auth-token",
            max_age=86400
        )

        return data

    except (BadSignature, SignatureExpired):

        return None


def require_auth():

    token = get_bearer_token()

    if not token:
        return None

    return verify_auth_token(token)


# ============================================================
# THREAT DETECTION ENGINE
# ============================================================

def detect_severity(event_type, status, message):

    event_type = (
        event_type or ""
    ).upper()

    status = (
        status or ""
    ).upper()

    message = (
        message or ""
    ).lower()

    # --------------------------------------------------------
    # CRITICAL THREATS
    # --------------------------------------------------------

    critical_events = [
        "MALWARE_ALERT",
        "MALWARE_DETECTED",
        "RANSOMWARE"
    ]

    if event_type in critical_events:

        return "CRITICAL"

    # --------------------------------------------------------
    # HIGH THREATS
    # --------------------------------------------------------

    high_events = [
        "BRUTE_FORCE",
        "SUSPICIOUS_LOGIN",
        "INTRUSION",
        "EXPLOIT_ATTEMPT",
        "UNAUTHORIZED_ACCESS"
    ]

    if event_type in high_events:

        return "HIGH"

    # --------------------------------------------------------
    # MESSAGE BASED THREAT DETECTION
    # --------------------------------------------------------

    dangerous_keywords = [
        "attack",
        "malware",
        "exploit",
        "unauthorized",
        "intrusion",
        "brute force",
        "ransomware",
        "sql injection",
        "xss"
    ]

    for keyword in dangerous_keywords:

        if keyword in message:

            return "HIGH"

    # --------------------------------------------------------
    # MEDIUM THREATS
    # --------------------------------------------------------

    if (
        event_type == "LOGIN_FAILURE"
        and status == "FAILED"
    ):

        return "MEDIUM"

    # --------------------------------------------------------
    # DEFAULT
    # --------------------------------------------------------

    return "LOW"


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({
        "project": "CyberSentinel",
        "description": "AI-powered Cybersecurity Threat Detection and SOC Monitoring Platform",
        "status": "online",
        "version": "3.0",
        "authentication": "Google OAuth + Bearer Token",
        "database": "PostgreSQL"
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({

        "project": "CyberSentinel",

        "service":
            "Cybersecurity Threat Detection and SOC Monitoring API",

        "status":
            "online",

        "database":
            "online",

        "authentication":
            "Google OAuth + Bearer Token",

        "version":
            "3.0"
    })


# ============================================================
# GOOGLE LOGIN
# ============================================================

@app.route("/api/auth/google", methods=["GET"])
def google_login():

    if not GOOGLE_CLIENT_ID:

        return jsonify({
            "success": False,
            "message": "Google Client ID is not configured"
        }), 500

    state_data = {
        "provider": "google",
        "created": datetime.utcnow().isoformat()
    }

    state = serializer.dumps(
        state_data,
        salt="google-oauth"
    )

    google_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        "?client_id="
        + GOOGLE_CLIENT_ID
        + "&redirect_uri="
        + GOOGLE_REDIRECT_URI
        + "&response_type=code"
        "&scope=openid%20email%20profile"
        "&access_type=offline"
        "&prompt=select_account"
        "&state="
        + state
    )

    return redirect(google_url)


# ============================================================
# GOOGLE CALLBACK
# ============================================================

@app.route("/api/auth/google/callback", methods=["GET"])
def google_callback():

    try:

        code = request.args.get("code")
        state = request.args.get("state")

        if not code:

            return redirect(
                FRONTEND_URL + "/?error=google_login_failed"
            )

        if not state:

            return redirect(
                FRONTEND_URL + "/?error=missing_state"
            )

        # ----------------------------------------------------
        # VERIFY STATE
        # ----------------------------------------------------

        try:

            serializer.loads(
                state,
                salt="google-oauth",
                max_age=600
            )

        except SignatureExpired:

            return redirect(
                FRONTEND_URL + "/?error=state_expired"
            )

        except BadSignature:

            return redirect(
                FRONTEND_URL + "/?error=invalid_state"
            )

        # ----------------------------------------------------
        # EXCHANGE CODE FOR ACCESS TOKEN
        # ----------------------------------------------------

        token_response = requests.post(

            "https://oauth2.googleapis.com/token",

            data={

                "client_id":
                    GOOGLE_CLIENT_ID,

                "client_secret":
                    GOOGLE_CLIENT_SECRET,

                "code":
                    code,

                "grant_type":
                    "authorization_code",

                "redirect_uri":
                    GOOGLE_REDIRECT_URI
            },

            timeout=20
        )

        token_data = token_response.json()

        access_token = token_data.get(
            "access_token"
        )

        if not access_token:

            print(
                "Google token error:",
                token_data
            )

            return redirect(
                FRONTEND_URL
                + "/?error=token_exchange_failed"
            )

        # ----------------------------------------------------
        # GET GOOGLE USER INFORMATION
        # ----------------------------------------------------

        user_response = requests.get(

            "https://www.googleapis.com/oauth2/v3/userinfo",

            headers={
                "Authorization":
                    "Bearer " + access_token
            },

            timeout=20
        )

        user_data = user_response.json()

        if not user_data.get("email"):

            return redirect(
                FRONTEND_URL
                + "/?error=user_information_failed"
            )

        # ----------------------------------------------------
        # CREATE CYBERSENTINEL AUTH TOKEN
        # ----------------------------------------------------

        auth_data = {

            "sub":
                user_data.get("sub"),

            "email":
                user_data.get("email"),

            "name":
                user_data.get("name"),

            "picture":
                user_data.get("picture")
        }

        auth_token = create_auth_token(
            auth_data
        )

        # ----------------------------------------------------
        # REDIRECT TO FRONTEND
        # ----------------------------------------------------

        return redirect(

            FRONTEND_URL
            + "/?auth_token="
            + auth_token
        )

    except Exception as error:

        print(
            "Google authentication error:",
            error
        )

        return redirect(
            FRONTEND_URL
            + "/?error=authentication_error"
        )


# ============================================================
# CURRENT USER
# ============================================================

@app.route("/api/auth/me", methods=["GET"])
def current_user():

    user = require_auth()

    if not user:

        return jsonify({

            "success":
                False,

            "authenticated":
                False,

            "message":
                "Authentication required"

        }), 401

    return jsonify({

        "success":
            True,

        "authenticated":
            True,

        "user":
            user

    })


# ============================================================
# LOGOUT
# ============================================================

@app.route("/api/auth/logout", methods=["POST"])
def logout():

    return jsonify({

        "success":
            True,

        "message":
            "Logged out successfully"

    })


# ============================================================
# CREATE SECURITY LOG
# ============================================================

@app.route("/api/logs", methods=["POST"])
def create_log():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        event_type = data.get(
            "event_type",
            "UNKNOWN"
        )

        source_ip = data.get(
            "source_ip",
            "Unknown"
        )

        username = data.get(
            "username",
            "Unknown"
        )

        status = data.get(
            "status",
            "UNKNOWN"
        )

        message = data.get(
            "message",
            ""
        )

        # ----------------------------------------------------
        # SERVER-SIDE THREAT DETECTION
        # ----------------------------------------------------

        severity = detect_severity(

            event_type,

            status,

            message
        )

        # ----------------------------------------------------
        # CREATE TIMESTAMP EXPLICITLY
        # ----------------------------------------------------

        event_time = datetime.utcnow()

        # ----------------------------------------------------
        # DATABASE RECORD
        # ----------------------------------------------------

        log = SecurityLog(

            event_type=event_type,

            source_ip=source_ip,

            username=username,

            status=status,

            severity=severity,

            message=message,

            created_at=event_time
        )

        db.session.add(log)

        db.session.commit()

        return jsonify({

            "success":
                True,

            "message":
                "Security event recorded",

            "log": {

                "id":
                    log.id,

                "event_type":
                    log.event_type,

                "source_ip":
                    log.source_ip,

                "username":
                    log.username,

                "status":
                    log.status,

                "severity":
                    log.severity,

                "message":
                    log.message,

                "created_at":
                    log.created_at.isoformat()
                    if log.created_at
                    else None
            }

        }), 201

    except Exception as error:

        db.session.rollback()

        print(
            "Log creation error:",
            error
        )

        return jsonify({

            "success":
                False,

            "message":
                "Failed to record security event",

            "error":
                str(error)

        }), 500


# ============================================================
# GET SECURITY LOGS
# ============================================================

@app.route("/api/logs", methods=["GET"])
def get_logs():

    user = require_auth()

    if not user:

        return jsonify({

            "success":
                False,

            "message":
                "Authentication required"

        }), 401

    try:

        logs = SecurityLog.query.order_by(

            SecurityLog.id.desc()

        ).limit(100).all()

        result = []

        for log in logs:

            result.append({

                "id":
                    log.id,

                "event_type":
                    log.event_type,

                "source_ip":
                    log.source_ip,

                "username":
                    log.username,

                "status":
                    log.status,

                "severity":
                    log.severity,

                "message":
                    log.message,

                "created_at":
                    log.created_at.isoformat()
                    if log.created_at
                    else None
            })

        return jsonify({

            "success":
                True,

            "count":
                len(result),

            "logs":
                result

        })

    except Exception as error:

        print(
            "Get logs error:",
            error
        )

        return jsonify({

            "success":
                False,

            "message":
                "Failed to retrieve security logs"

        }), 500


# ============================================================
# SECURITY SUMMARY
# ============================================================

@app.route("/api/security-summary", methods=["GET"])
def security_summary():

    user = require_auth()

    if not user:

        return jsonify({

            "success":
                False,

            "message":
                "Authentication required"

        }), 401

    try:

        total_events = SecurityLog.query.count()

        high_threats = SecurityLog.query.filter_by(
            severity="HIGH"
        ).count()

        critical_threats = SecurityLog.query.filter_by(
            severity="CRITICAL"
        ).count()

        medium_threats = SecurityLog.query.filter_by(
            severity="MEDIUM"
        ).count()

        low_threats = SecurityLog.query.filter_by(
            severity="LOW"
        ).count()

        return jsonify({

            "success":
                True,

            "summary": {

                "total_events":
                    total_events,

                "high_threats":
                    high_threats,

                "critical_threats":
                    critical_threats,

                "medium_threats":
                    medium_threats,

                "low_threats":
                    low_threats
            }

        })

    except Exception as error:

        print(
            "Security summary error:",
            error
        )

        return jsonify({

            "success":
                False,

            "message":
                "Failed to generate security summary"

        }), 500


# ============================================================
# API INFORMATION
# ============================================================

@app.route("/api", methods=["GET"])
def api_information():

    return jsonify({

        "project":
            "CyberSentinel",

        "version":
            "3.0",

        "status":
            "online",

        "endpoints": {

            "health":
                "/api/health",

            "google_login":
                "/api/auth/google",

            "current_user":
                "/api/auth/me",

            "security_logs":
                "/api/logs",

            "security_summary":
                "/api/security-summary",

            "logout":
                "/api/auth/logout"
        },

        "security_features": [

            "Google OAuth Authentication",

            "Bearer Token Authentication",

            "Security Log Monitoring",

            "Threat Severity Detection",

            "Brute Force Detection",

            "Suspicious Login Detection",

            "Malware Alert Detection",

            "Intrusion Detection",

            "PostgreSQL Database",

            "External Security Agent",

            "Cloud Deployment"
        ]

    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({

        "success":
            False,

        "message":
            "API endpoint not found"

    }), 404


@app.errorhandler(500)
def internal_error(error):

    db.session.rollback()

    return jsonify({

        "success":
            False,

        "message":
            "Internal server error"

    }), 500


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
