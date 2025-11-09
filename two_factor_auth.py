import pyotp
import qrcode
import io
from PIL import Image
from urllib.parse import quote

class TwoFactorAuthManager:
    def __init__(self):
        pass

    def generate_secret(self):
        return pyotp.random_base32()

    def get_provisioning_uri(self, secret, email, full_name, issuer_name="SecureVault", image_url=None):
        # Note: Google Authenticator shows the first letter of issuer_name
        # Other apps (Authy, Microsoft Authenticator) may support custom image_url
        if full_name:
            account_name = f"{email} ({full_name})"
        else:
            account_name = email
        
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer_name)
        if image_url:
            uri += f"&image={quote(image_url, safe='')}"
        return uri
        
    def generate_qr_code(self, uri, logo_path=None):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H, # Higher error correction for logo
            box_size=6,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

        if logo_path:
            logo = Image.open(logo_path)
            
            #
            basewidth = 100
            wpercent = (basewidth/float(logo.size[0]))
            hsize = int((float(logo.size[1])*float(wpercent)))
            logo = logo.resize((basewidth, hsize), Image.LANCZOS)
            pos = ((img.size[0] - logo.size[0]) // 2, (img.size[1] - logo.size[1]) // 2)
            img.paste(logo, pos)

        byte_arr = io.BytesIO()
        img.save(byte_arr, format='PNG')
        byte_arr.seek(0)
        return byte_arr

    def verify_code(self, secret, code):
        totp = pyotp.TOTP(secret)
        return totp.verify(code)