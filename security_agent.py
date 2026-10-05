import requests
import socket
import platform
import time
import random

# LIVE CYBERSENTINEL SERVER
API_URL = "https://cybersentinel-qcl5.onrender.com/api/logs"


def get_device_information():
    return {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "os_version": platform.version(),
        "processor": platform.processor()
    }


def create_security_event(device):
    events = [
        {
            "event_type": "AGENT_SECURITY_EVENT",
            "status": "DETECTED",
            "message": "External security agent detected a monitoring event",
            "severity": "LOW"
        },
        {
            "event_type": "LOGIN_FAILURE",
            "status": "FAILED",
            "message": "Failed login attempt detected by external security agent",
            "severity": "MEDIUM"
        },
        {
            "event_type": "SUSPICIOUS_LOGIN",
            "status": "SUCCESS",
            "message": "Suspicious login detected from external device",
            "severity": "HIGH"
        },
        {
            "event_type": "BRUTE_FORCE",
            "status": "FAILED",
            "message": "Multiple failed login attempts detected",
            "severity": "HIGH"
        },
        {
            "event_type": "MALWARE_ALERT",
            "status": "DETECTED",
            "message": "Possible malware activity detected by security agent",
            "severity": "CRITICAL"
        }
    ]

    event = random.choice(events)

    event["source_ip"] = "192.168.1.100"
    event["username"] = device["hostname"]

    return event


def send_security_event():

    device = get_device_information()
    event = create_security_event(device)

    try:

        response = requests.post(
            API_URL,
            json=event,
            timeout=15
        )

        print()
        print("=" * 60)
        print("          CYBERSENTINEL SECURITY AGENT")
        print("=" * 60)

        print("Device Name      :", device["hostname"])
        print("Operating System :", device["operating_system"])
        print("OS Version       :", device["os_version"])
        print("Processor        :", device["processor"])

        print("-" * 60)

        print("Server           :", API_URL)
        print("Event Type       :", event["event_type"])
        print("Source IP        :", event["source_ip"])
        print("Username         :", event["username"])
        print("Status           :", event["status"])
        print("Severity         :", event["severity"])
        print("Message          :", event["message"])

        print("-" * 60)

        print("HTTP Status      :", response.status_code)

        try:
            print("Server Response  :", response.json())
        except Exception:
            print("Server Response  :", response.text)

        print("=" * 60)

    except requests.exceptions.ConnectionError:

        print()
        print("ERROR: Cannot connect to CyberSentinel live server.")
        print("Check your internet connection.")

    except requests.exceptions.Timeout:

        print()
        print("ERROR: Server connection timed out.")

    except Exception as error:

        print()
        print("ERROR:", error)


if __name__ == "__main__":

    print()
    print("=" * 60)
    print("      CYBERSENTINEL EXTERNAL SECURITY AGENT")
    print("=" * 60)
    print("Live monitoring started...")
    print("Cloud Server:", API_URL)
    print("Press CTRL+C to stop.")
    print()

    while True:

        send_security_event()

        print()
        print("Next security event will be sent in 15 seconds...")
        print()

        time.sleep(15)
