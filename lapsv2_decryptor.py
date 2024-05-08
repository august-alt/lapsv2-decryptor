import ldap3
import sys
import dpapi_ng

# Define the attribute list
attribute_list = [
    "msLAPS-PasswordExpirationTime",
    "msLAPS-Password",
    "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedPasswordHistory",
    "msLAPS-EncryptedDSRMPassword",
    "msLAPS-EncryptedDSRMPasswordHistory",
    "ms-Mcs-AdmPwd",
    "ms-Mcs-AdmPwdExpirationTime"
]

# Check the number of command-line arguments
if len(sys.argv) != 3:
    print(f"Usage: python {sys.argv[0]} <DN> <DC>")
    print(f"Example: python {sys.argv[0]} 'CN=DC01,OU=LAPSManaged,DC=domain,DC=alt' 'dc01.domain.alt'")
    sys.exit(1)

dn = sys.argv[1]
dc = sys.argv[2]

# Create an LDAP connection
ldap_connection = ldap3.Connection(dc, auto_bind=True)

# Define the search filter
search_filter = f"(distinguishedName={dn})"

# Perform the LDAP search
ldap_connection.search(dn, search_filter, attributes=attribute_list)

# Get the search results
search_results = ldap_connection.entries

# Check if the computer object was found
if len(search_results) != 1:
    print("[!] Could not find computer object")
    sys.exit(1)

# Process the search results
for attribute_name, attribute_values in search_results[0].items():
    if attribute_name.lower() == "mslaps-passwordexpirationtime":
        expiry = attribute_values[0]
        print("[*] Expiry time is:", expiry)
    elif attribute_name.lower() == "mslaps-password":
        unencrypted_password = attribute_values[0]
        print("[*] Unencrypted Password:", unencrypted_password)
    elif attribute_name.lower() == "mslaps-encryptedpassword":
        encrypted_password = attribute_values[0]
        print("[*] Found encrypted password of length:", len(encrypted_password))
        decrypted_password = decrypt(encrypted_password[16:])
        print("[*] Decrypted Password:", decrypted_password)

# Close the LDAP connection
ldap_connection.unbind()

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
