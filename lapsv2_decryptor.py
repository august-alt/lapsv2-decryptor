import ldap3
import sys
import dpapi_ng
import gssapi

# Define the decryption function
def decrypt(encrypted_data):
    dpapiCache = dpapi_ng.KeyCache()
    decrypted = dpapi_ng.ncrypt_unprotect_secret(
        encrypted_data, 
        server = None,
		username = None,
		password = None,
		cache = dpapiCache
    )
    return decrypted.decode('utf-8').replace("\x00", "")

# Define the attribute list
attribute_list = [
    "msLAPS-PasswordExpirationTime",
    "msLAPS-Password",
    "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedPasswordHistory",
    "msLAPS-EncryptedDSRMPassword",
    "msLAPS-EncryptedDSRMPasswordHistory"
]

# Check the number of command-line arguments
if len(sys.argv) != 3:
    print(f"Usage: python {sys.argv[0]} <DN> <DC>")
    print(f"Example: python {sys.argv[0]} 'CN=DC01,OU=LAPSManaged,DC=domain,DC=alt' 'dc01.domain.alt'")
    sys.exit(1)

dn = sys.argv[1]
dc = sys.argv[2]

# Create an LDAP connection
server = ldap3.Server(dc, get_info=ldap3.ALL)
ldap_connection = ldap3.Connection(server, auto_bind=True, client_strategy=ldap3.SYNC, authentication=ldap3.SASL, check_names=True, sasl_mechanism='GSSAPI')

# Define the search filter
search_filter = "(objectclass=computer)"

# Perform the LDAP search
ldap_connection.search(dn, search_filter, attributes=attribute_list)

# Get the search results
search_results = ldap_connection.entries

# Check if the computer object was found
if len(search_results) != 1:
    print(f"[!] Could not find computer object {search_results} {dn} {dc}")
    sys.exit(1)

# Process the search results
entry = search_results[0]
expiry = entry["msLAPS-PasswordExpirationTime"]
print("[*] Expiry time is:", expiry)
encrypted_password = entry["msLAPS-EncryptedPassword"].raw_values[0]
print("[*] Found encrypted password of length:", len(encrypted_password))
decrypted_password = decrypt(encrypted_password[16:])
print("[*] Decrypted Password:", decrypted_password)

# Close the LDAP connection
ldap_connection.unbind()

