import requests
import socket
import platform
import time
import random

API_URL = "http://127.0.0.1:5000/api/logs"


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
        }
    ]

    event = random.choice(events)

    event["source_ip"] = "192.168.1.100"
    event["username"] = device["hostname"]

    return event


def send_event():

    device = get_device_information()

    event = create_security_event(device)

    try:

        response = requests.post(
            API_URL,
            json=event,
            timeout=5
        )

        print()
        print("=" * 55)
        print("        CYBERSENTINEL SECURITY AGENT")
        print("=" * 55)

        print("Device Name :", device["hostname"])
        print("Operating System :", device["operating_system"])
        print("OS Version :", device["os_version"])
        print("Server :", API_URL)

        print("-" * 55)

        print("Event Type :", event["event_type"])
        print("Status :", event["status"])
        print("Severity :", event["severity"])

        print("-" * 55)

        print("HTTP Status :", response.status_code)
        print("Server Response :", response.json())

        print("=" * 55)

    except requests.exceptions.ConnectionError:

        print()
        print("ERROR: CyberSentinel backend is not running.")
        print("Start backend first.")

    except requests.exceptions.Timeout:

        print()
        print("ERROR: Backend connection timed out.")

    except Exception as error:

        print()
        print("ERROR:", error)


if __name__ == "__main__":

    print()
    print("CyberSentinel External Security Agent")
    print("Starting security monitoring...")
    print()

    while True:

        send_event()

        print()
        print("Next monitoring event in 15 seconds...")
        print("Press CTRL+C to stop.")

        time.sleep(15)