'''
import jwt
import jws
import ecdsa
sk256 = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
vk = sk256.get_verifying_key()
header = { 'alg': 'ES256' }
payload = { 'claim': 'JSON is the raddest.', 'iss': 'brianb' }
sig = jws.sign(header, payload, sk256)
print(jws.verify(header, payload, sig, vk))
'''
#------

from signedjson.key import generate_signing_key, get_verify_key, encode_signing_key_base64, decode_signing_key_base64
from signedjson.sign import (
    sign_json, verify_signed_json, SignatureVerifyException
)

signing_key = generate_signing_key('zxcvb')
signed_json = sign_json({'my_key': 'my_data'}, 'CDF', signing_key)
print(signed_json)

#Going into function
verify_key = get_verify_key(signing_key)
print("Going into function",verify_key)

enc = encode_signing_key_base64(verify_key)
print("Base64 encoded:", enc)

print("This will go into function")
print(decode_signing_key_base64("ed25519","zxcvb",enc))

try:
    verify_signed_json(signed_json, 'CDF', verify_key)
    print('Signature is valid')
except SignatureVerifyException:
    print('Signature is invalid')
