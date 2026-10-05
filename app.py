import os
from datetime import timedelta

from flask import Flask, jsonify, request, session, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


# ============================================================
# FRONTEND URL
# ============================================================

FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "https://cyber-sentinel-navy.vercel.app"
)


# ============================================================
# SESSION CONFIGURATION
# ============================================================

app.config.update(

    SECRET_KEY=os.getenv(
        "FLASK_SECRET_KEY",
        "dev-secret-key"
    ),

    SESSION_COOKIE_SECURE=True,

    SESSION_COOKIE_HTTPONLY=True,

    SESSION_COOKIE_SAMESITE="None",

    PERMANENT_SESSION_LIFETIME=timedelta(
        hours=2
    ),

    SQLALCHEMY_TRACK_MODIFICATIONS=False
)


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

database_url = os.getenv("DATABASE_URL")


if database_url:

    # Render PostgreSQL URL
    if database_url.startswith("postgresql://"):
        database_url = database_url.replace(
            "postgresql://",
            "postgresql+psycopg2://",
            1
        )

    # Older postgres URL format
    elif database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://",
            "postgresql+psycopg2://",
            1
        )

    # If psycopg driver URL is supplied
    elif database_url.startswith(
        "postgresql+psycopg://"
    ):
        database_url = database_url.replace(
            "postgresql+psycopg://",
            "postgresql+psycopg2://",
            1
        )

else:

    # Local fallback database
    database_url = "sqlite:///cybersentinel.db"


app.config["SQLALCHEMY_DATABASE_URI"] = database_url


# ============================================================
# DATABASE
# ============================================================

db = SQLAlchemy(app)


# ============================================================
# CORS
# ============================================================

CORS(
    app,

    resources={
        r"/api/*": {
            "origins": [
                FRONTEND_URL
            ]
        }
    },

    supports_credentials=True
)


# ============================================================
# OAUTH
# ============================================================

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


# ============================================================
# GOOGLE OAUTH REGISTRATION
# ============================================================

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


# ============================================================
# SECURITY LOG MODEL
# ============================================================

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
        db.String(20),
        nullable=False,
        default="LOW"
    )

    message = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )


# ============================================================
# THREAT DETECTION ENGINE
# ============================================================

def detect_threat(
    event_type,
    status="",
    message=""
):

    event_type = (
        event_type or ""
    ).upper()

    status = (
        status or ""
    ).upper()

    message = (
        message or ""
    ).lower()


    # Critical threats

    if event_type == "MALWARE_ALERT":

        return "CRITICAL"


    # High threats

    if event_type in [
        "BRUTE_FORCE",
        "SUSPICIOUS_LOGIN",
        "INTRUSION",
        "RANSOMWARE"
    ]:

        return "HIGH"


    # Failed login

    if (
        event_type == "LOGIN_FAILURE"
        and status == "FAILED"
    ):

        return "MEDIUM"


    # Suspicious keywords

    suspicious_keywords = [

        "attack",
        "malware",
        "exploit",
        "unauthorized",
        "intrusion",
        "brute force",
        "ransomware"

    ]


    for keyword in suspicious_keywords:

        if keyword in message:

            return "HIGH"


    return "LOW"


# ============================================================
# GOOGLE LOGIN
# ============================================================

@app.route(
    "/api/auth/google",
    methods=["GET"]
)
def google_login():

    if not GOOGLE_CLIENT_ID:

        return jsonify({
            "error": "Google OAuth is not configured"
        }), 500


    redirect_uri = (
        GOOGLE_REDIRECT_URI
    )


    return oauth.google.authorize_redirect(
        redirect_uri
    )


# ============================================================
# GOOGLE CALLBACK
# ============================================================

@app.route(
    "/api/auth/google/callback",
    methods=["GET"]
)
def google_callback():

    try:

        token = (
            oauth.google.authorize_access_token()
        )


        user_info = token.get(
            "userinfo"
        )


        if not user_info:

            user_info = (
                oauth.google.userinfo()
            )


        if not user_info:

            return jsonify({
                "error":
                    "Unable to retrieve Google user information"
            }), 401


        # ====================================================
        # CREATE SESSION
        # ====================================================

        session.permanent = True


        session["user"] = {

            "name": user_info.get(
                "name",
                "CyberSentinel User"
            ),

            "email": user_info.get(
                "email",
                ""
            ),

            "picture": user_info.get(
                "picture",
                ""
            )
        }


        session.modified = True


        print(
            "Google authentication successful:",
            user_info.get("email")
        )


        # ====================================================
        # REDIRECT TO VERCEL
        # ====================================================

        return redirect(
            FRONTEND_URL
        )


    except Exception as error:

        print(
            "Google authentication error:",
            error
        )


        return jsonify({

            "error":
                "Google authentication failed",

            "details":
                str(error)

        }), 500


# ============================================================
# CHECK CURRENT SESSION
# ============================================================

@app.route(
    "/api/auth/me",
    methods=["GET"]
)
def current_user():

    user = session.get(
        "user"
    )


    if not user:

        return jsonify({

            "authenticated": False

        })


    return jsonify({

        "authenticated": True,

        "user": user

    })


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/api/auth/logout",
    methods=["GET"]
)
def logout():

    session.clear()


    return jsonify({

        "success": True,

        "message":
            "Logged out successfully"

    })


# ============================================================
# ROOT
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return jsonify({

        "project":
            "CyberSentinel",

        "service":
            "Cybersecurity Threat Detection and SOC Monitoring API",

        "status":
            "online",

        "authentication":
            "Google OAuth",

        "database":
            "online",

        "version":
            "2.0"

    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    database_status = "offline"


    try:

        db.session.execute(
            db.text("SELECT 1")
        )

        database_status = "online"

    except Exception as error:

        print(
            "Database health error:",
            error
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
            "2.0"

    })


# ============================================================
# CREATE SECURITY LOG
# ============================================================

@app.route(
    "/api/logs",
    methods=["POST"]
)
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
            ""
        )

        username = data.get(
            "username",
            ""
        )

        status = data.get(
            "status",
            ""
        )

        message = data.get(
            "message",
            ""
        )


        severity = detect_threat(

            event_type,

            status,

            message

        )


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


        return jsonify({

            "success": True,

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
            "Create log error:",
            error
        )


        return jsonify({

            "success": False,

            "error":
                str(error)

        }), 500


# ============================================================
# GET SECURITY LOGS
# ============================================================

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
            .limit(100)
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
                    if log.created_at
                    else None

            })


        return jsonify({

            "success": True,

            "logs": result

        })


    except Exception as error:

        print(
            "Get logs error:",
            error
        )


        return jsonify({

            "success": False,

            "error":
                str(error),

            "logs": []

        }), 500


# ============================================================
# SECURITY SUMMARY
# ============================================================

@app.route(
    "/api/security-summary",
    methods=["GET"]
)
def security_summary():

    try:

        total = SecurityLog.query.count()


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


    except Exception as error:

        print(
            "Security summary error:",
            error
        )


        return jsonify({

            "error":
                str(error)

        }), 500


# ============================================================
# INITIALIZE DATABASE
# ============================================================

with app.app_context():

    try:

        db.create_all()

        print(
            "Database tables initialized successfully."
        )

    except Exception as error:

        print(
            "Database initialization error:",
            error
        )


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                5000
            )
        ),
        debug=False
    )
