import os
import socket

from dotenv import load_dotenv


load_dotenv()


class Config:

    SIEM_AGENT_URL = os.getenv(
        "SIEM_AGENT_URL",
        "http://127.0.0.1:6000"
    )

    SECRET_KEY = os.getenv(
        "SECRET_KEY"
    )

    COLLECTOR_ID = os.getenv(
        "COLLECTOR_ID",
        "windows-collector"
    )

    HOSTNAME = socket.gethostname()

    HEARTBEAT_INTERVAL = int(
        os.getenv(
            "HEARTBEAT_INTERVAL",
            30
        )
    )

    POLL_INTERVAL = int(
        os.getenv(
            "POLL_INTERVAL",
            5
        )
    )

    MAX_EVENTS_PER_READ = int(
        os.getenv(
            "MAX_EVENTS_PER_READ",
            50
        )
    )

    WINDOWS_EVENT_IDS = {

        # ==========================
        # Audit Policy & Log Integrity
        # ==========================
        1102,   # Security log cleared
        4719,   # System audit policy changed

        # ==========================
        # Authentication
        # ==========================
        4624,   # Successful login
        4625,   # Failed login
        4634,   # Logoff
        4648,   # Explicit credentials
        4672,   # Special privileges assigned

        # ==========================
        # Process Monitoring
        # ==========================
        4688,   # Process created
        4689,   # Process terminated

        # ==========================
        # Account Management
        # ==========================
        4720,   # User account created
        4722,   # User account enabled
        4723,   # Password change attempt
        4724,   # Password reset
        4725,   # User account disabled
        4726,   # User account deleted

        # ==========================
        # Group Management
        # ==========================
        4732,   # User added to security group
        4733,   # User removed from security group

        # ==========================
        # Account Security
        # ==========================
        4740,   # Account locked

        # ==========================
        # Kerberos / NTLM
        # ==========================
        4768,   # Kerberos TGT requested
        4769,   # Kerberos service ticket requested
        4771,   # Kerberos pre-authentication failed
        4776,   # NTLM authentication

        # ==========================
        # Windows Filtering Platform
        # ==========================
        5156,   # Connection allowed
        5157,   # Connection blocked
    }