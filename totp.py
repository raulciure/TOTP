from time import time
from Crypto.Hash import HMAC, SHA256


class Totp:
    def __init__(self, key, output_digits = 6, t_interval = 30, t_start = 0):
        if not(6 <= output_digits <= 10):
            raise ValueError("output_digits must be in [6, 10]")

        self.__KEY = key
        self.__OUTPUT_DIGITS = output_digits    # The number of digits of the output code (6 - 10)
        self.__T_INTERVAL = t_interval      # Interval for which the OTP is valid
        self.__T_START = t_start    # Start time of the epoch

    def __truncate(self, hash : bytes):
        offset = hash[-1] & 0x0F    # Take the last(least significant) 4 bits of the last hash byte => offset int
        truncated_hash = hash[offset : offset + 4]      # Take 4 bytes (32 bits) starting from the offset index
        return int.from_bytes(truncated_hash) & 0x7FFFFFFF      # Mask the first bit (sign bit) and convert the bits to an integer

    def __generate_otp(self, counter : int):
        otp_hash = HMAC.new(self.__KEY, counter.to_bytes(4), digestmod=SHA256)      # Generate an HMAC tag for the counter (4 bytes value)
        otp_int = self.__truncate(otp_hash.digest()) % (10 ** self.__OUTPUT_DIGITS)     # HMAC tag (digest) truncated and generated HOTP/TOTP code by reducing to __OUTPUT_DIGITS digits
        return str(otp_int).zfill(self.__OUTPUT_DIGITS)     # Pad with zeros on the left, in case integer code started with 0

    def generate(self, set_t : int | None = None):
        if(set_t == None):  # Use current time
            current_t = time()
            counter = int((current_t - self.__T_START) / self.__T_INTERVAL)
        else:   # Use set_t time
            counter = int((set_t - self.__T_START) / self.__T_INTERVAL)

        return self.__generate_otp(counter)
    
    def verify(self, otp : str, set_t : int | None = None):
        if(set_t == None):  # Use current time
            current_t = time()
            counter = int((current_t - self.__T_START) / self.__T_INTERVAL)
        else:   # Use set_t time
            counter = int((set_t - self.__T_START) / self.__T_INTERVAL)

        gen_otp = self.__generate_otp(counter)
        if(gen_otp == otp):
            return True
        return False
