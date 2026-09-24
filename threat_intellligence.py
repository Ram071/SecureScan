import requests

from config import VIRUSTOTAL_API_KEY

def lookup_file_hash(sha256):

if not VIRUSTOTAL_API_KEY:

    return {
        "enabled": False,
        "message":
            "External threat intelligence "
            "is not configured."
    }

endpoint = (
    "https://www.virustotal.com/api/v3/files/"
    + sha256
)

headers = {
    "x-apikey": VIRUSTOTAL_API_KEY
}

try:

    response = requests.get(
        endpoint,
        headers=headers,
        timeout=10
    )

    if response.status_code == 404:

        return {
            "enabled": True,
            "found": False,
            "message": "Hash not found."
        }

    response.raise_for_status()

    data = response.json()

    attributes = (
        data.get("data", {})
        .get("attributes", {})
    )

    return {
        "enabled": True,
        "found": True,
        "stats": attributes.get(
            "last_analysis_stats",
            {}
        )
    }

except requests.RequestException:

    return {
        "enabled": True,
        "error":
            "Threat-intelligence request failed."
    }
