import hashlib
import random
import time
import re

import requests

from config import (
    ROUTER_URL,
    ROUTER_USERNAME,
    ROUTER_PASSWORD,
)


# The router firmware uses this path when calculating HA2,
# even though the actual request is sent to /xml_action.cgi?method=set.
DIGEST_URI = "/cgi/xml_action.cgi"

# This is the CSRF value used by the router's JavaScript.
# Keep it configurable so firmware changes can be handled without
# changing the code.
ROUTER_CSRF_TOKEN = "hfiehifejfklihefiuehflejhfueihfeuihfeui"


def md5_hex(value):
    return hashlib.md5(
        value.encode("utf-8")
    ).hexdigest()


class RouterClient:

    def __init__(self):
        self.base_url = ROUTER_URL.rstrip("/")

        self.username = ROUTER_USERNAME
        self.password = ROUTER_PASSWORD

        self.session = requests.Session()

        self.session.headers.update({
            "Accept": "application/xml, text/xml, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/151.0.0.0 Safari/537.36"
            ),
        })

        self.realm = None
        self.nonce = None
        self.qop = None

        # Firmware starts GnCount at 1.
        self.nc = 1

    # ---------------------------------------------------------
    # Authentication challenge
    # ---------------------------------------------------------

    def get_auth_challenge(self):
        """
        Ask /login.cgi for the Digest WWW-Authenticate challenge.
        """

        url = f"{self.base_url}/login.cgi"

        response = self.session.get(
            url,
            timeout=15,
        )

        challenge = response.headers.get(
            "WWW-Authenticate"
        )

        if not challenge:
            raise RuntimeError(
                "Router did not return WWW-Authenticate"
            )

        if not challenge.startswith("Digest"):
            raise RuntimeError(
                f"Unsupported authentication scheme: {challenge}"
            )

        self.realm = self._get_digest_value(
            challenge,
            "realm"
        )

        self.nonce = self._get_digest_value(
            challenge,
            "nonce"
        )

        self.qop = self._get_digest_value(
            challenge,
            "qop"
        )

        if not self.realm:
            raise RuntimeError(
                "Digest realm was not found"
            )

        if not self.nonce:
            raise RuntimeError(
                "Digest nonce was not found"
            )

        if not self.qop:
            raise RuntimeError(
                "Digest qop was not found"
            )

        print(
            f"[AUTH] Realm: {self.realm}"
        )

        print(
            f"[AUTH] QOP: {self.qop}"
        )

        return challenge

    @staticmethod
    def _get_digest_value(header, name):
        """
        Extract a quoted Digest parameter.
        """

        match = re.search(
            rf'{name}="([^"]+)"',
            header,
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

        return None

    # ---------------------------------------------------------
    # Router's custom Digest calculation
    # ---------------------------------------------------------

    def _build_digest(self, method):
        """
        Reproduce the router firmware's getAuthHeader().
        """

        ha1 = md5_hex(
            f"{self.username}:{self.realm}:{self.password}"
        )

        ha2 = md5_hex(
            f"{method}:{DIGEST_URI}"
        )

        # Router JavaScript:
        #
        # rand = Math.floor(Math.random()*100001)
        # date = new Date().getTime()
        # salt = rand + "" + date
        # cnonce = MD5(salt).substring(0,16)

        rand = random.randint(
            0,
            100000
        )

        timestamp_ms = int(
            time.time() * 1000
        )

        salt = f"{rand}{timestamp_ms}"

        cnonce = md5_hex(
            salt
        )[:16]

        nc = f"{self.nc:08X}"

        response = md5_hex(
            f"{ha1}:"
            f"{self.nonce}:"
            f"{nc}:"
            f"{cnonce}:"
            f"{self.qop}:"
            f"{ha2}"
        )

        # Match the router's JavaScript formatting.
        authorization = (
            'Digest '
            f'username="{self.username}", '
            f'realm="{self.realm}", '
            f'nonce="{self.nonce}", '
            f'uri="{DIGEST_URI}", '
            f'response="{response}", '
            f'qop={self.qop}, '
            f'nc={nc}, '
            f'cnonce="{cnonce}"'
        )

        self.nc += 1

        return authorization

    # ---------------------------------------------------------
    # Login
    # ---------------------------------------------------------

    def login(self):
        """
        Reproduce the router's doLogin() flow.
        """

        print("[AUTH] Getting Digest challenge...")

        self.get_auth_challenge()

        # The router's doLogin() calculates:
        #
        # HA1 = MD5(username:realm:password)
        # HA2 = MD5(GET:/cgi/xml_action.cgi)
        #
        # and uses GnCount = 1 for the login response.

        ha1 = md5_hex(
            f"{self.username}:{self.realm}:{self.password}"
        )

        ha2 = md5_hex(
            f"GET:{DIGEST_URI}"
        )

        rand = random.randint(
            0,
            100000
        )

        timestamp_ms = int(
            time.time() * 1000
        )

        salt = f"{rand}{timestamp_ms}"

        cnonce = md5_hex(
            salt
        )[:16]

        nc = "00000001"

        digest_response = md5_hex(
            f"{ha1}:"
            f"{self.nonce}:"
            f"{nc}:"
            f"{cnonce}:"
            f"{self.qop}:"
            f"{ha2}"
        )

        params = {
            "Action": "Digest",
            "username": self.username,
            "realm": self.realm,
            "nonce": self.nonce,
            "response": digest_response,
            "qop": self.qop,
            "cnonce": cnonce,
            "nc": nc,
            "temp": "marvell",
        }

        url = f"{self.base_url}/login.cgi"

        # The router's doLogin() calls authentication(url),
        # which sends a GET with the Authorization header.
        authorization = (
            'Digest '
            f'username="{self.username}", '
            f'realm="{self.realm}", '
            f'nonce="{self.nonce}", '
            f'uri="{DIGEST_URI}", '
            f'response="{digest_response}", '
            f'qop={self.qop}, '
            f'nc={nc}, '
            f'cnonce="{cnonce}"'
        )

        response = self.session.get(
            url,
            params=params,
            headers={
                "Authorization": authorization,
            },
            timeout=15,
        )

        print(
            f"[AUTH] Login HTTP status: "
            f"{response.status_code}"
        )

        print(
            f"[AUTH] Login response: "
            f"{response.text[:500]}"
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Router login failed: "
                f"{response.status_code}"
            )

        # Firmware's doLogin() leaves GnCount at 1,
        # so the first subsequent API call uses 00000001.
        self.nc = 1

        return True

    # ---------------------------------------------------------
    # Network activity
    # ---------------------------------------------------------

    def get_network_activity(self):
        """
        Retrieve the actual router Access/Network Activity log.
        """

        if not self.realm:
            self.login()

        url = (
            f"{self.base_url}"
            "/xml_action.cgi?method=set"
        )

        payload = """<?xml version="1.0" encoding="US-ASCII"?>
<RGW>
    <param>
        <method>call</method>
        <session>000</session>
        <obj_path>cm</obj_path>
        <obj_method>get_network_activity</obj_method>
    </param>
</RGW>"""

        authorization = self._build_digest(
            "POST"
        )

        headers = {
            "Authorization": authorization,
            "csrftoken": ROUTER_CSRF_TOKEN,
            "Content-Type": (
                "application/x-www-form-urlencoded; "
                "charset=UTF-8"
            ),
        }

        response = self.session.post(
            url,
            data=payload,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()

        # Router can return HTTP 200 while putting the
        # actual authorization failure inside XML.
        if "<error_cause>5</error_cause>" in response.text:
            print(
                "[AUTH] Router rejected authorization. "
                "Refreshing authentication..."
            )

            self.realm = None
            self.nonce = None
            self.qop = None
            self.nc = 1

            self.login()

            return self.get_network_activity()

        return response.text