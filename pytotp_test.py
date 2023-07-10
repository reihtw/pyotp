import pyotp

totp = pyotp.TOTP('base32secret3232')
print(totp.now())
