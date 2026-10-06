import os
import urllib.parse
from datetime import timedelta

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, redirect
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)


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
).rstrip("/")


# ============================================================
# FLASK CONFIGURATION
# ============================================================

app.config.update(

    SECRET_KEY=os.getenv(
        "FLASK_SECRET_KEY",
        "dev-secret-key-change-this"
    ),

    SQLALCHEMY_TRACK_MODIFICATIONS=False,

    PERMANENT_SESSION_LIFETIME=timedelta(
        hours=2
    )
)


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

database_url = os.getenv("DATABASE_URL")


if database_url:

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

    elif database_url.startswith(
        "postgresql+psycopg://"
    ):

        database_url = database_url.replace(
            "postgresql+psycopg://",
            "postgresql+psycopg2://",
            1
        )

else:

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

    supports_credentials=False
)


# ============================================================
# GOOGLE OAUTH CONFIGURATION
# ============================================================

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


GOOGLE_AUTH_URL = (
    "https://accounts.google.com/o/oauth2/v2/auth"
)

GOOGLE_TOKEN_URL = (
    "https://oauth2.googleapis.com/token"
)

GOOGLE_USERINFO_URL = (
    "https://www.googleapis.com/oauth2/v2/userinfo"
)


# ============================================================
# SIGNED STATE SERIALIZER
#
# IMPORTANT:
# This replaces Authlib's Flask-session state handling.
# Therefore the Vercel -> Render session mismatch is avoided.
# ============================================================

state_serializer = URLSafeTimedSerializer(
    app.config["SECRET_KEY"],
    salt="cybersentinel-google-state"
)


# ============================================================
# AUTH TOKEN SERIALIZER
#
# This is the token used by the frontend.
# ============================================================

auth_serializer = URLSafeTimedSerializer(
    app.config["SECRET_KEY"],
    salt="cybersentinel-auth-token"
)


# ============================================================
# CREATE AUTH TOKEN
# ============================================================

def create_auth_token(user):

    return auth_serializer.dumps({

        "email": user.get(
            "email",
            ""
        ),

        "name": user.get(
            "name",
            "CyberSentinel User"
        ),

        "picture": user.get(
            "picture",
            ""
        )

    })


# ============================================================
# GET CURRENT USER FROM BEARER TOKEN
# ============================================================

def get_current_user():

    authorization = request.headers.get(
        "Authorization",
        ""
    )


    if not authorization.startswith(
        "Bearer "
    ):

        return None


    token = authorization[
        7:
    ].strip()


    if not token:

        return None


    try:

        data = auth_serializer.loads(
            token,
            max_age=7200
        )

        return {

            "email":
                data.get(
                    "email",
                    ""
                ),

            "name":
                data.get(
                    "name",
                    "CyberSentinel User"
                ),

            "picture":
                data.get(
                    "picture",
                    ""
                )

        }

    except (
        SignatureExpired,
        BadSignature
    ):

        return None

    except Exception as error:

        print(
            "Token validation error:",
            error
        )

        return None


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


    # --------------------------------------------------------
    # CRITICAL
    # --------------------------------------------------------

    critical_events = [

        "MALWARE_ALERT",

        "MALWARE_DETECTED",

        "RANSOMWARE"

    ]


    if event_type in critical_events:

        return "CRITICAL"


    # --------------------------------------------------------
    # HIGH
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
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    suspicious_keywords = [

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


    for keyword in suspicious_keywords:

        if keyword in message:

            return "HIGH"


    # --------------------------------------------------------
    # FAILED LOGIN
    # --------------------------------------------------------

    if (
        event_type == "LOGIN_FAILURE"
        and status == "FAILED"
    ):

        return "MEDIUM"


    return "LOW"


# ============================================================
# GOOGLE LOGIN
# ============================================================

@app.route(
    "/api/auth/google",
    methods=["GET"]
)
def google_login():

    try:

        if not GOOGLE_CLIENT_ID:

            return jsonify({

                "error":
                    "Google OAuth is not configured"

            }), 500


        # ----------------------------------------------------
        # Create signed state
        # ----------------------------------------------------

        state = state_serializer.dumps({

            "provider":
                "google",

            "frontend":
                FRONTEND_URL

        })


        # ----------------------------------------------------
        # Google authorization parameters
        # ----------------------------------------------------

        params = {

            "client_id":
                GOOGLE_CLIENT_ID,

            "redirect_uri":
                GOOGLE_REDIRECT_URI,

            "response_type":
                "code",

            "scope":
                "openid email profile",

            "state":
                state,

            "access_type":
                "offline",

            "prompt":
                "select_account"

        }


        google_url = (
            GOOGLE_AUTH_URL
            + "?"
            + urllib.parse.urlencode(
                params
            )
        )


        return redirect(
            google_url
        )


    except Exception as error:

        print(
            "Google login error:",
            error
        )


        return jsonify({

            "error":
                "Google authentication initialization failed",

            "details":
                str(error)

        }), 500


# ============================================================
# GOOGLE CALLBACK
# ============================================================

@app.route(
    "/api/auth/google/callback",
    methods=["GET"]
)
def google_callback():

    try:

        # ----------------------------------------------------
        # Get Google callback parameters
        # ----------------------------------------------------

        code = request.args.get(
            "code"
        )

        state = request.args.get(
            "state"
        )


        if not code:

            return jsonify({

                "error":
                    "Missing Google authorization code"

            }), 400


        if not state:

            return jsonify({

                "error":
                    "Missing Google authentication state"

            }), 400


        # ----------------------------------------------------
        # Verify signed state
        # ----------------------------------------------------

        try:

            state_data = (
                state_serializer.loads(
                    state,
                    max_age=600
                )
            )

        except SignatureExpired:

            return jsonify({

                "error":
                    "Google authentication state expired"

            }), 400

        except BadSignature:

            return jsonify({

                "error":
                    "Invalid Google authentication state"

            }), 400


        # ----------------------------------------------------
        # Validate provider
        # ----------------------------------------------------

        if (
            state_data.get(
                "provider"
            )
            != "google"
        ):

            return jsonify({

                "error":
                    "Invalid authentication provider"

            }), 400


        # ----------------------------------------------------
        # Exchange Google code for access token
        # ----------------------------------------------------

        token_response = requests.post(

            GOOGLE_TOKEN_URL,

            data={

                "code":
                    code,

                "client_id":
                    GOOGLE_CLIENT_ID,

                "client_secret":
                    GOOGLE_CLIENT_SECRET,

                "redirect_uri":
                    GOOGLE_REDIRECT_URI,

                "grant_type":
                    "authorization_code"

            },

            timeout=15

        )


        if token_response.status_code != 200:

            print(
                "Google token exchange error:",
                token_response.text
            )


            return jsonify({

                "error":
                    "Google token exchange failed"

            }), 500


        token_data = (
            token_response.json()
        )


        access_token = (
            token_data.get(
                "access_token"
            )
        )


        if not access_token:

            return jsonify({

                "error":
                    "Google access token missing"

            }), 500


        # ----------------------------------------------------
        # Get Google user information
        # ----------------------------------------------------

        user_response = requests.get(

            GOOGLE_USERINFO_URL,

            headers={

                "Authorization":
                    "Bearer "
                    + access_token

            },

            timeout=15

        )


        if user_response.status_code != 200:

            print(
                "Google user info error:",
                user_response.text
            )


            return jsonify({

                "error":
                    "Unable to retrieve Google user information"

            }), 500


        user_info = (
            user_response.json()
        )


        email = user_info.get(
            "email"
        )


        name = user_info.get(
            "name",
            "CyberSentinel User"
        )


        picture = user_info.get(
            "picture",
            ""
        )


        if not email:

            return jsonify({

                "error":
                    "Google account email not available"

            }), 400


        print(
            "Google authentication successful:",
            email
        )


        # ----------------------------------------------------
        # Create CyberSentinel bearer token
        # ----------------------------------------------------

        auth_token = create_auth_token({

            "email":
                email,

            "name":
                name,

            "picture":
                picture

        })


        # ----------------------------------------------------
        # Redirect to Vercel
        # ----------------------------------------------------

        frontend_url = (
            state_data.get(
                "frontend",
                FRONTEND_URL
            )
        )


        redirect_url = (

            frontend_url
            + "/?auth_token="
            + urllib.parse.quote(
                auth_token,
                safe=""
            )

        )


        return redirect(
            redirect_url
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
# CHECK CURRENT USER
# ============================================================

@app.route(
    "/api/auth/me",
    methods=["GET"]
)
def current_user():

    user = get_current_user()


    if not user:

        return jsonify({

            "authenticated":
                False,

            "message":
                "Authentication required"

        }), 401


    return jsonify({

        "authenticated":
            True,

        "user":
            user

    })


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/api/auth/logout",
    methods=["POST"]
)
def logout():

    return jsonify({

        "success":
            True,

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
            "Google OAuth + Bearer Token",

        "database":
            "online",

        "version":
            "3.0"

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
            "Google OAuth + Bearer Token",

        "version":
            "3.0"

    })


# ============================================================
# CREATE SECURITY LOG
#
# This endpoint remains available to the external
# security agent.
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
            "Create log error:",
            error
        )


        return jsonify({

            "success":
                False,

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

    user = get_current_user()


    if not user:

        return jsonify({

            "authenticated":
                False,

            "error":
                "Authentication required"

        }), 401


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

            "success":
                True,

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

            "error":
                str(error),

            "logs":
                []

        }), 500


# ============================================================
# SECURITY SUMMARY
# ============================================================

@app.route(
    "/api/security-summary",
    methods=["GET"]
)
def security_summary():

    user = get_current_user()


    if not user:

        return jsonify({

            "authenticated":
                False,

            "error":
                "Authentication required"

        }), 401


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
# DATABASE INITIALIZATION
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
