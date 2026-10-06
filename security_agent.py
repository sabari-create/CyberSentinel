import requests
import socket
import platform
import time
import random


# ============================================================
# CYBERSENTINEL LIVE CLOUD API
# ============================================================

API_URL = "https://cybersentinel-qcl5.onrender.com/api/logs"


# ============================================================
# GET LOCAL DEVICE INFORMATION
# ============================================================

def get_device_information():

    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "Unknown"

    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "operating_system": platform.system(),
        "os_version": platform.version(),
        "processor": platform.processor()
    }


# ============================================================
# CREATE SECURITY EVENT
# ============================================================

def create_security_event(device):

    events = [

        {
            "event_type": "AGENT_SECURITY_EVENT",
            "status": "DETECTED",
            "message":
                "External security agent detected a monitoring event"
        },

        {
            "event_type": "LOGIN_FAILURE",
            "status": "FAILED",
            "message":
                "Failed login attempt detected by external security agent"
        },

        {
            "event_type": "SUSPICIOUS_LOGIN",
            "status": "SUCCESS",
            "message":
                "Suspicious login detected from external device"
        },

        {
            "event_type": "BRUTE_FORCE",
            "status": "FAILED",
            "message":
                "Multiple failed login attempts detected"
        },

        {
            "event_type": "MALWARE_ALERT",
            "status": "DETECTED",
            "message":
                "Possible malware activity detected by security agent"
        }

    ]

    event = random.choice(events)

    event["source_ip"] = device["local_ip"]

    event["username"] = device["hostname"]

    return event


# ============================================================
# SEND EVENT TO CLOUD
# ============================================================

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
        print("=" * 65)
        print("          CYBERSENTINEL SECURITY AGENT")
        print("=" * 65)

        print(
            "Device Name      :",
            device["hostname"]
        )

        print(
            "Local IP         :",
            device["local_ip"]
        )

        print(
            "Operating System :",
            device["operating_system"]
        )

        print(
            "OS Version       :",
            device["os_version"]
        )

        print(
            "Processor        :",
            device["processor"]
        )

        print("-" * 65)

        print(
            "Cloud API        :",
            API_URL
        )

        print(
            "Event Type       :",
            event["event_type"]
        )

        print(
            "Source IP        :",
            event["source_ip"]
        )

        print(
            "Username         :",
            event["username"]
        )

        print(
            "Status           :",
            event["status"]
        )

        print(
            "Message          :",
            event["message"]
        )

        print("-" * 65)

        print(
            "HTTP Status      :",
            response.status_code
        )


        try:

            server_response = response.json()

            print(
                "Server Response  :",
                server_response
            )

        except Exception:

            print(
                "Server Response  :",
                response.text
            )


        print("=" * 65)


    except requests.exceptions.ConnectionError:

        print()
        print(
            "ERROR: Cannot connect to CyberSentinel cloud server."
        )

        print(
            "Check your internet connection."
        )


    except requests.exceptions.Timeout:

        print()
        print(
            "ERROR: CyberSentinel server connection timed out."
        )


    except Exception as error:

        print()
        print(
            "ERROR:",
            error
        )


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 65)
    print("       CYBERSENTINEL EXTERNAL SECURITY AGENT")
    print("=" * 65)

    print()
    print("External device monitoring started.")
    print()
    print("Cloud Server:")
    print(API_URL)

    print()
    print("Events are sent every 15 seconds.")

    print()
    print("Press CTRL+C to stop the agent.")
    print()


    try:

        while True:

            send_security_event()

            print()
            print(
                "Next security event in 15 seconds..."
            )

            time.sleep(15)


    except KeyboardInterrupt:

        print()
        print("=" * 65)
        print("CyberSentinel Security Agent stopped.")
        print("=" * 65)
