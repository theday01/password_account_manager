import pyotp
import qrcode
import io

class TwoFactorAuthManager:
    def __init__(self):
        pass

    def generate_secret(self):
        return pyotp.random_base32()

    def get_provisioning_uri(self, secret, email, full_name, issuer_name="SecureVault"):
        if full_name:
            issuer_name = f"{issuer_name} ({full_name})"
        
        return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer_name)

    def generate_qr_code(self, uri):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=6,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        
        byte_arr = io.BytesIO()
        img.save(byte_arr, format='PNG')
        byte_arr.seek(0)
        return byte_arr

    def verify_code(self, secret, code):
        totp = pyotp.TOTP(secret)
        return totp.verify(code)