# 🛡️ CyberSentinel

### AI-Powered Cybersecurity Threat Detection & SOC Monitoring Platform

**CyberSentinel** is a cloud-based cybersecurity monitoring platform designed to collect, detect, classify, and visualize security events from connected devices through a centralized Security Operations Center (SOC) dashboard.

The system demonstrates an end-to-end cybersecurity workflow:

```text
External Device
      ↓
Security Agent
      ↓
Internet / Network
      ↓
REST API
      ↓
Threat Detection Engine
      ↓
PostgreSQL Database
      ↓
SOC Monitoring Dashboard
      ↓
Security Alerts & Visualization
```

---

## 🌐 Live Application

### Frontend / SOC Dashboard

https://cyber-sentinel-navy.vercel.app/

### Backend API

https://cybersentinel-qcl5.onrender.com/

---

## 🎯 Project Objective

The main objective of CyberSentinel is to provide centralized visibility into security events generated from external devices.

The platform helps demonstrate how security events can be:

* Collected from external devices
* Sent securely to a cloud backend
* Stored in a centralized database
* Classified according to threat severity
* Displayed through a SOC-style dashboard
* Monitored from another device over the network

---

## 🚨 Problem Statement

Traditional systems may generate security events across different devices, making it difficult to maintain centralized visibility.

CyberSentinel addresses this problem by providing a centralized monitoring platform where security events from external devices can be sent to a cloud-hosted backend and displayed in a SOC dashboard.

---

## 🔐 Cybersecurity Features

CyberSentinel currently provides rule-based security event detection and classification.

### Threat Categories

| Event Type             | Severity |
| ---------------------- | -------- |
| MALWARE_ALERT          | CRITICAL |
| MALWARE_DETECTED       | CRITICAL |
| RANSOMWARE             | CRITICAL |
| BRUTE_FORCE            | HIGH     |
| SUSPICIOUS_LOGIN       | HIGH     |
| INTRUSION              | HIGH     |
| EXPLOIT_ATTEMPT        | HIGH     |
| UNAUTHORIZED_ACCESS    | HIGH     |
| LOGIN_FAILURE + FAILED | MEDIUM   |
| Other monitored events | LOW      |

The system automatically assigns a severity level based on the security event type and message.

---

## 🖥️ External Device Integration

CyberSentinel includes a Python-based security agent that can run on an external Windows device.

The agent collects basic device information such as:

* Hostname
* Local IP address
* Operating system
* Event timestamp

It then sends a security event to the live CyberSentinel REST API.

### Demonstration Flow

```text
External Windows Laptop
        ↓
security_agent.py
        ↓
POST /api/logs
        ↓
CyberSentinel Backend
        ↓
Threat Detection
        ↓
PostgreSQL
        ↓
SOC Dashboard
```

A controlled external-device test event was successfully sent from another laptop and displayed on the live dashboard.

A controlled `BRUTE_FORCE` security test was also used to demonstrate **HIGH severity** classification.

> These events are controlled demonstration/test events and do not represent a real attack or malware infection.

---

## 🏗️ System Architecture

```text
                 ┌───────────────────────┐
                 │   External Device     │
                 │   Windows Laptop      │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │  CyberSentinel Agent  │
                 │     Python Agent      │
                 └───────────┬───────────┘
                             │
                             ▼
                    Internet / Network
                             │
                             ▼
                 ┌───────────────────────┐
                 │     Flask REST API    │
                 │    Render Backend     │
                 └───────────┬───────────┘
                             │
                    Threat Detection
                             │
                             ▼
                 ┌───────────────────────┐
                 │   PostgreSQL Cloud    │
                 │       Database        │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │    SOC Dashboard      │
                 │   HTML / CSS / JS     │
                 │       Vercel          │
                 └───────────────────────┘
```

---

## 🧰 Technology Stack

### Frontend

* HTML5
* CSS3
* JavaScript
* Vercel

### Backend

* Python
* Flask
* Flask-SQLAlchemy
* REST API
* Gunicorn
* Render

### Database

* PostgreSQL

### Security

* Rule-based threat detection
* Security event classification
* Severity analysis
* Bearer token authentication
* Google OAuth authentication
* External security monitoring agent

### Development & Deployment

* Git
* GitHub
* Vercel
* Render
* PostgreSQL

---

## 🔑 Authentication

CyberSentinel supports Google-based authentication for accessing protected dashboard APIs.

The application uses:

* Google OAuth
* Signed authentication state
* Bearer token authentication
* Protected security summary and log APIs

Authentication helps prevent unauthorized access to security monitoring information.

---

## 🔌 REST API

### Health Check

```http
GET /api/health
```

Used to verify that the backend service is running.

### Create Security Event

```http
POST /api/logs
```

Used by the external security agent to send security events.

Example request:

```json
{
  "event_type": "BRUTE_FORCE",
  "source_ip": "10.99.113.185",
  "username": "Kishore",
  "status": "FAILED",
  "message": "Multiple failed login attempts detected during security test"
}
```

### Retrieve Security Logs

```http
GET /api/logs
```

Returns monitored security events.

### Security Summary

```http
GET /api/security-summary
```

Returns dashboard statistics such as:

* Total events
* High threats
* Critical threats
* Medium threats

---

## 📊 SOC Monitoring Dashboard

The dashboard provides centralized visibility into security events.

It displays:

* Total security events
* High-threat events
* Critical-threat events
* Medium-threat events
* Event type
* Source IP
* Username/device
* Status
* Severity
* Timestamp

This provides a simple SOC-style view for monitoring security activity.

---

## ☁️ Cloud Deployment

CyberSentinel is deployed using cloud platforms.

| Component      | Platform       |
| -------------- | -------------- |
| Frontend       | Vercel         |
| Backend        | Render         |
| Database       | PostgreSQL     |
| Source Code    | GitHub         |
| External Agent | Windows Laptop |

The application is accessible over the internet and can be demonstrated from a device other than the development machine.

---

## 📁 Project Structure

```text
CyberSentinel/
│
├── frontend/
│   ├── index.html
│   └── vercel.json
│
├── app.py
├── models.py
├── requirements.txt
├── security_agent.py
├── vercel.json
└── README.md
```

---

## ⚙️ Running the Security Agent

Clone the repository:

```bash
git clone https://github.com/sabari-create/CyberSentinel.git
```

Move into the project directory:

```bash
cd CyberSentinel
```

Install the required Python package:

```bash
py -m pip install requests
```

Run the external security agent:

```bash
py security_agent.py
```

The agent sends a controlled security event to the live CyberSentinel backend.

---

## 🧪 Demonstration

The project can be demonstrated using the following workflow:

```text
1. Open CyberSentinel live dashboard
2. Login using Google authentication
3. Open the external laptop
4. Run security_agent.py
5. Agent collects device information
6. Agent sends event to REST API
7. Backend receives the event
8. Threat detection classifies the event
9. Event is stored in PostgreSQL
10. Event appears on the SOC dashboard
```

A controlled brute-force event can also be generated to demonstrate HIGH severity classification.

---

## 📈 Project Results

CyberSentinel successfully demonstrates:

* Cloud-hosted cybersecurity monitoring
* REST API communication
* PostgreSQL database integration
* External device integration
* Security event collection
* Rule-based threat classification
* SOC dashboard visualization
* Google authentication
* Live deployment using Vercel and Render

---

## 🔮 Future Scope

Future versions of CyberSentinel can include:

* Machine-learning-based anomaly detection
* Real-time WebSocket alerts
* Email/SMS security notifications
* Automated incident response
* IP reputation checking
* VirusTotal integration
* Network traffic monitoring
* SIEM integration
* Advanced analytics
* Threat intelligence feeds
* Automated security reports

---

## ⚠️ Current Limitation

The current threat classification system is **rule-based**.

Although machine-learning libraries may be included in the project environment, the current deployed version should not be considered a fully trained ML-based threat detection system.

Future versions can add trained machine-learning models for anomaly and threat detection.

---

## 👨‍💻 Developer

**SABARI K**

B.Sc Digital & Cyber Forensic Science
Rathinam Global Deemed to be University
Coimbatore, Tamil Nadu, India

---

## 📌 Project Links

**GitHub Repository:**
https://github.com/sabari-create/CyberSentinel

**Live SOC Dashboard:**
https://cyber-sentinel-navy.vercel.app/

**Live Backend API:**
https://cybersentinel-qcl5.onrender.com/

---

## ⭐ Project Summary

CyberSentinel demonstrates an end-to-end cloud cybersecurity monitoring workflow where an external device generates a security event, the event is transmitted through a REST API, classified by the security layer, stored in PostgreSQL, and displayed on a live SOC monitoring dashboard.

```text
External Device
      ↓
Security Agent
      ↓
REST API
      ↓
Threat Detection
      ↓
PostgreSQL
      ↓
SOC Dashboard
```

**CyberSentinel — From Security Events to Centralized Security Visibility.**
