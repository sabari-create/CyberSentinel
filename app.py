import os
from datetime import datetime, timedelta

from flask import Flask, jsonify, request, redirect, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from sqlalchemy import text


# =========================================================
# CYBERSENTINEL
# Cybersecurity Threat Detection and SOC Monitoring API
# =========================================================


# =========================================================
# APP CONFIGURATION
# =========================================================

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.getenv(
        "FLASK_SECRET_KEY",
        "CyberSentinel_Default_Secret_Key"
    ),

    # Secure cross-site session for:
    # Vercel Frontend <-> Render Backend
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",

    # Session lifetime
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),

    # SQLAlchemy
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)


# =========================================================
# FRONTEND CONFIGURATION
# =========================================================

FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "https://cyber-sentinel-navy.vercel.app"
)


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

database_url = os.getenv("DATABASE_URL")


if database_url:

    # Render PostgreSQL URL
    # Convert to psycopg2 driver

    if database_url.startswith("postgresql://"):

        database_url = database_url.replace(
            "postgresql://",
            "postgresql+psycopg2://",
            1
        )

    elif database_url.startswith("postgres://"):

        database_url = database_url.replace(
            "postgres://",
            "postgresql+psycopg2://",
            1
        )

    elif database_url.startswith("postgresql+psycopg://"):

        database_url = database_url.replace(
            "postgresql+psycopg://",
            "postgresql+psycopg2://",
            1
        )

else:

    # Local development fallback
    database_url = "sqlite:///cybersentinel.db"


app.config["SQLALCHEMY_DATABASE_URI"] = database_url


db = SQLAlchemy(app)


# =========================================================
# CORS CONFIGURATION
# =========================================================

CORS(
    app,
    supports_credentials=True,
    origins=[
        FRONTEND_URL
    ]
)


# =========================================================
# GOOGLE OAUTH CONFIGURATION
# =========================================================

oauth = OAuth(app)


GOOGLE_CLIENT_ID = os.getenv(
    "GOOGLE_CLIENT_ID"
)

GOOGLE_CLIENT_SECRET = os.getenv(
    "GOOGLE_CLIENT_SECRET"
)

GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://cybersentinel-qcl5.onrender.com/api/auth/google/callback"
)


# =========================================================
# REGISTER GOOGLE OAUTH
# =========================================================

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:

    oauth.register(

        name="google",

        client_id=GOOGLE_CLIENT_ID,

        client_secret=GOOGLE_CLIENT_SECRET,

        server_metadata_url=(
            "https://accounts.google.com/.well-known/"
            "openid-configuration"
        ),

        client_kwargs={
            "scope": "openid email profile"
        }

    )


# =========================================================
# DATABASE MODEL
# =========================================================

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
        db.String(100),
        nullable=True
    )

    username = db.Column(
        db.String(100),
        nullable=True
    )

    status = db.Column(
        db.String(50),
        nullable=True
    )

    severity = db.Column(
        db.String(50),
        nullable=False
    )

    message = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# =========================================================
# THREAT DETECTION ENGINE
# =========================================================

def detect_threat(
    event_type,
    status="",
    message=""
):

    event_type = str(
        event_type
    ).upper()

    status = str(
        status
    ).upper()

    message = str(
        message
    ).lower()


    # -----------------------------------------------------
    # CRITICAL THREATS
    # -----------------------------------------------------

    if event_type in [

        "MALWARE_ALERT",

        "RANSOMWARE",

        "DATA_BREACH"

    ]:

        return "CRITICAL"


    # -----------------------------------------------------
    # HIGH THREATS
    # -----------------------------------------------------

    if event_type in [

        "BRUTE_FORCE",

        "SUSPICIOUS_LOGIN",

        "INTRUSION",

        "PORT_SCAN",

        "UNAUTHORIZED_ACCESS"

    ]:

        return "HIGH"


    # -----------------------------------------------------
    # FAILED LOGIN
    # -----------------------------------------------------

    if (

        event_type == "LOGIN_FAILURE"

        and

        status == "FAILED"

    ):

        return "MEDIUM"


    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    suspicious_keywords = [

        "attack",

        "malware",

        "exploit",

        "unauthorized",

        "intrusion",

        "ransomware",

        "sql injection",

        "brute force"

    ]


    for keyword in suspicious_keywords:

        if keyword in message:

            return "HIGH"


    # -----------------------------------------------------
    # DEFAULT
    # -----------------------------------------------------

    return "LOW"


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

with app.app_context():

    try:

        db.create_all()

        print(
            "Database tables initialized successfully."
        )

    except Exception as e:

        print(
            "Database initialization error:",
            e
        )


# =========================================================
# HOME API
# =========================================================

@app.route("/")
def home():

    return jsonify({

        "project":
            "CyberSentinel",

        "service":
            "Cybersecurity Threat Detection and SOC Monitoring API",

        "status":
            "online",

        "version":
            "3.0",

        "authentication":
            "Google OAuth",

        "database":
            "PostgreSQL"

    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health")
def health():

    database_status = "offline"


    try:

        db.session.execute(
            text("SELECT 1")
        )

        database_status = "online"


    except Exception as e:

        print(
            "Database health error:",
            e
        )


    return jsonify({

        "project":
            "CyberSentinel",

        "service":
            "Cybersecurity Threat Detection and SOC Monitoring API",

        "status":
            "online",

        "database":
            database_status,

        "authentication":
            "Google OAuth",

        "version":
            "3.0"

    })


# =========================================================
# GOOGLE LOGIN
# =========================================================

@app.route("/api/auth/google")
def google_login():

    if not GOOGLE_CLIENT_ID:

        return jsonify({

            "error":
                "GOOGLE_CLIENT_ID is not configured"

        }), 500


    if not GOOGLE_CLIENT_SECRET:

        return jsonify({

            "error":
                "GOOGLE_CLIENT_SECRET is not configured"

        }), 500


    try:

        return oauth.google.authorize_redirect(

            GOOGLE_REDIRECT_URI

        )


    except Exception as e:

        print(
            "Google login error:",
            e
        )

        return jsonify({

            "error":
                "Unable to start Google authentication",

            "details":
                str(e)

        }), 500


# =========================================================
# GOOGLE CALLBACK
# =========================================================

@app.route("/api/auth/google/callback")
def google_callback():

    try:

        # -------------------------------------------------
        # Exchange authorization code for Google token
        # -------------------------------------------------

        token = (
            oauth.google
            .authorize_access_token()
        )


        # -------------------------------------------------
        # Get Google user information
        # -------------------------------------------------

        user_info = token.get(
            "userinfo"
        )


        if not user_info:

            user_info = (
                oauth.google
                .userinfo()
            )


        if not user_info:

            return jsonify({

                "error":
                    "Unable to retrieve Google user information"

            }), 401


        # -------------------------------------------------
        # Store authenticated user in Flask session
        # -------------------------------------------------

        session.permanent = True


        session["user"] = {

            "name":
                user_info.get(
                    "name",
                    "CyberSentinel User"
                ),

            "email":
                user_info.get(
                    "email",
                    ""
                ),

            "picture":
                user_info.get(
                    "picture",
                    ""
                )

        }


        # -------------------------------------------------
        # Force session save
        # -------------------------------------------------

        session.modified = True


        print(
            "Google authentication successful:",
            user_info.get(
                "email",
                ""
            )
        )


        # -------------------------------------------------
        # Redirect to Vercel frontend
        # -------------------------------------------------

        return redirect(
            FRONTEND_URL
        )


    except Exception as e:

        print(
            "Google OAuth error:",
            e
        )

        return jsonify({

            "error":
                "Google authentication failed",

            "details":
                str(e)

        }), 500


# =========================================================
# CURRENT USER
# =========================================================

@app.route("/api/auth/me")
def current_user():

    user = session.get(
        "user"
    )


    if not user:

        return jsonify({

            "authenticated":
                False

        }), 200


    return jsonify({

        "authenticated":
            True,

        "user":
            user

    }), 200


# =========================================================
# LOGOUT
# =========================================================

@app.route("/api/auth/logout")
def logout():

    session.clear()


    return jsonify({

        "success":
            True,

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

    try:

        data = request.get_json(
            silent=True
        )


        if not data:

            return jsonify({

                "success":
                    False,

                "error":
                    "JSON body required"

            }), 400


        # -------------------------------------------------
        # Extract event data
        # -------------------------------------------------

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


        # -------------------------------------------------
        # Threat detection
        # -------------------------------------------------

        severity = detect_threat(

            event_type,

            status,

            message

        )


        # -------------------------------------------------
        # Create database record
        # -------------------------------------------------

        log = SecurityLog(

            event_type=event_type,

            source_ip=source_ip,

            username=username,

            status=status,

            severity=severity,

            message=message

        )


        db.session.add(
            log
        )

        db.session.commit()


        # -------------------------------------------------
        # Return created event
        # -------------------------------------------------

        return jsonify({

            "success":
                True,

            "message":
                "Security event recorded",

            "event": {

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

            }

        }), 201


    except Exception as e:

        db.session.rollback()


        print(
            "Create log error:",
            e
        )


        return jsonify({

            "success":
                False,

            "error":
                "Unable to create security event"

        }), 500


# =========================================================
# GET SECURITY LOGS
# =========================================================

@app.route(
    "/api/logs",
    methods=["GET"]
)
def get_logs():

    try:

        logs = (
            SecurityLog.query
            .order_by(
                SecurityLog.created_at.desc()
            )
            .all()
        )


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

            })


        return jsonify({

            "count":
                len(result),

            "logs":
                result

        })


    except Exception as e:

        print(
            "Get logs error:",
            e
        )


        return jsonify({

            "error":
                "Unable to retrieve security logs"

        }), 500


# =========================================================
# SECURITY SUMMARY
# =========================================================

@app.route(
    "/api/security-summary"
)
def security_summary():

    try:

        total = (
            SecurityLog.query.count()
        )


        critical = (
            SecurityLog.query
            .filter_by(
                severity="CRITICAL"
            )
            .count()
        )


        high = (
            SecurityLog.query
            .filter_by(
                severity="HIGH"
            )
            .count()
        )


        medium = (
            SecurityLog.query
            .filter_by(
                severity="MEDIUM"
            )
            .count()
        )


        low = (
            SecurityLog.query
            .filter_by(
                severity="LOW"
            )
            .count()
        )


        return jsonify({

            "total_events":
                total,

            "critical":
                critical,

            "high":
                high,

            "medium":
                medium,

            "low":
                low

        })


    except Exception as e:

        print(
            "Security summary error:",
            e
        )


        return jsonify({

            "error":
                "Unable to generate security summary"

        }), 500


# =========================================================
# APPLICATION START
# =========================================================

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
