from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(100))
    status = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), default="LOW")
    message = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "username": self.username,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "created_at": self.created_at.isoformat()
        }