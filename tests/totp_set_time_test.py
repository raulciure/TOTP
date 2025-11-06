import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from totp import Totp
import time


key = b'\x72\x05\x93\x2c\x70\x1e\x46\x52\x97\xa4'

generator = Totp(key, t_interval=1)
verifier = Totp(key, t_interval=1)

while True:
    generator_totp_code = generator.generate(50)
    verifier_totp_code = verifier.generate(50)

    print("Generator TOTP Code:", generator_totp_code[:3], generator_totp_code[3:])
    print("Verifier TOTP Code:", verifier_totp_code[:3], verifier_totp_code[3:])
    print("Is the TOTP verified?", verifier.verify(generator_totp_code, 50))
    print("-----------------------------------------\n")

    time.sleep(1)
