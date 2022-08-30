import hashlib
from enum import IntEnum
from Crypto.Cipher import AES


class Error(Exception):
    pass


class Encryption(IntEnum):
    AES = 0x0  # aes-gcm-128
    SPONGENT = 0x1  # spongent-128

    @staticmethod
    def from_str(str_):
        lower_str = str_.lower()

        if lower_str == "aes":
            return Encryption.AES
        if lower_str == "spongent":
            return Encryption.SPONGENT

        raise Error("No matching encryption type for {}".format(str_))

    def to_str(self):
        if self == Encryption.AES:
            return "aes"
        if self == Encryption.SPONGENT:
            return "spongent"

        raise Error("to_str not implemented for {}".format(self.name))

    def get_key_size(self):
        if self == Encryption.AES:
            return 16
        if self == Encryption.SPONGENT:
            return 16

        raise Error("get_key_size not implemented for {}".format(self.name))

    async def encrypt(self, key, ad, data):
        if self == Encryption.AES:
            return await encrypt_aes(key, ad, data)
        if self == Encryption.SPONGENT:
            return await encrypt_spongent(key, ad, data)

        raise Error("encrypt not implemented for {}".format(self.name))

    async def decrypt(self, key, ad, data):
        if self == Encryption.AES:
            return await decrypt_aes(key, ad, data)
        if self == Encryption.SPONGENT:
            return await decrypt_spongent(key, ad, data)

        raise Error("decrypt not implemented for {}".format(self.name))

    async def mac(self, key, ad):
        if self == Encryption.AES:
            return await encrypt_aes(key, ad)
        if self == Encryption.SPONGENT:
            return await encrypt_spongent(key, ad)

        raise Error("mac not implemented for {}".format(self.name))


async def encrypt_aes(key, ad, data=b''):
    # Note: we set nonce to zero because our nonce is part of the associated data
    aes_gcm = AES.new(key, AES.MODE_GCM, nonce=b'\x00'*12)
    aes_gcm.update(ad)
    cipher, tag = aes_gcm.encrypt_and_digest(data)
    return cipher + tag


async def decrypt_aes(key, ad, data=b''):
    try:
        aes_gcm = AES.new(key, AES.MODE_GCM, nonce=b'\x00'*12)
        aes_gcm.update(ad)

        cipher = data[:-16]
        tag = data[-16:]
        return aes_gcm.decrypt_and_verify(cipher, tag)
    except:
        raise Error("Decryption failed")


async def encrypt_spongent(key, ad, data=[]):
    try:
        import sancus.libsancuscrypt as sancus_crypto
    except:
        raise Error("Sancus python libraries not found in PYTHONPATH")

    cipher, tag = sancus_crypto.wrap(key, ad, data)
    return cipher + tag


async def decrypt_spongent(key, ad, data=[]):
    try:
        import sancus.libsancuscrypt as sancus_crypto
    except:
        raise Error("Sancus python libraries not found in PYTHONPATH")

    # data should be formed like this: [cipher, tag]
    tag_size = sancus_crypto.KEY_SIZE
    cipher = data[:-tag_size]
    tag = data[-tag_size:]

    plain = sancus_crypto.unwrap(key, ad, cipher, tag)

    if plain is None:
        raise Error("Decryption failed")

    return plain

def hash_sha256(data, size=32):
    if size > 32:
        raise Error(
            "SHA256 cannot compute digests with length {}".format(size))

    return hashlib.sha256(data).digest()[:size]
