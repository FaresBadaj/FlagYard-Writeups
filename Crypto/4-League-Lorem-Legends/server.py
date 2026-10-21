from Crypto.Util.number import bytes_to_long, getPrime

FLAG = "FlagY{REDACTED}"
e = getPrime(128)
p = getPrime(1024)
q = getPrime(1024)
n = p * q
c = pow(bytes_to_long(FLAG), e, n)

d = pow(e, -1, (p - 1) * (q - 1))
dp = d % (p - 1)
dp_high = dp >> 205

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print(f"{dp_high = }")