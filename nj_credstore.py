"""OS credential-store access for the NinjaOne connector.

Trust-boundary role: this is the ONLY module that touches the credentials at
rest. NinjaOne uses OAuth 2.0 client credentials — TWO secrets — held as ONE
item per platform, with an identical API behind each backend:

- Windows: a single generic credential in Windows Credential Manager (target
  "ninjaone-connector", DPAPI-protected per user), reached in-process via
  ctypes (advapi32 CredRead/CredWrite/CredDelete). UserName carries the Client
  ID, the credential blob carries the Client Secret. The secret never touches
  argv, stdin, the environment, or any child process at all.
- macOS: a single generic-password item in the login Keychain (service
  "ninjaone-connector", account = Client ID, password = Client Secret), via
  /usr/bin/security. The store path feeds the secret to `security -i` over
  stdin so it never appears in a process listing.

Neither value is ever written to a file, a log, or an environment variable.
Every retrieved secret is registered with the log-redaction filter before
anything else can log it. The bearer token minted from these credentials is
handled entirely in nj_api and never reaches this module or the disk.
"""

import re
import subprocess

from nj_common import IS_WINDOWS, RedactionFilter, redact

SERVICE = "ninjaone-connector"

# Charset gates. Besides rejecting obvious paste mistakes, on macOS they
# guarantee neither value can break out of the quoted `security -i` command
# line: no quotes, backslashes, dollar signs, backticks, whitespace, or
# control characters. The Windows backend passes no shell at all, but the same
# gate is applied on both platforms so a credential pair that works on one
# cannot be rejected by the other.
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._~-]{8,128}$")
CLIENT_SECRET_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{16,256}$")


class CredentialStoreError(RuntimeError):
    pass


# Backwards-compatible alias: the macOS tree calls this KeychainError.
KeychainError = CredentialStoreError


def _validate(client_id, client_secret):
    client_id = (client_id or "").strip()
    client_secret = (client_secret or "").strip()
    if not CLIENT_ID_RE.fullmatch(client_id):
        raise CredentialStoreError(
            "That does not look like a NinjaOne Client ID (expected 8-128 chars "
            "of letters/digits/._~-). Refusing to store it.")
    if not CLIENT_SECRET_RE.fullmatch(client_secret):
        raise CredentialStoreError(
            "That does not look like a NinjaOne Client Secret (expected 16-256 "
            "chars of letters/digits/._~+/=-). Refusing to store it.")
    return client_id, client_secret


# ===========================================================================
# Windows backend: Credential Manager via ctypes (in-process, DPAPI-backed)
# ===========================================================================

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _MAX_BLOB_BYTES = 5 * 512  # CRED_MAX_CREDENTIAL_BLOB_SIZE
    _CRED_TYPE_GENERIC = 1
    _CRED_PERSIST_LOCAL_MACHINE = 2  # per-user store, survives reboot

    class _CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    _PCREDENTIAL = ctypes.POINTER(_CREDENTIAL)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _advapi32.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                    wintypes.DWORD,
                                    ctypes.POINTER(_PCREDENTIAL)]
    _advapi32.CredReadW.restype = wintypes.BOOL
    _advapi32.CredWriteW.argtypes = [_PCREDENTIAL, wintypes.DWORD]
    _advapi32.CredWriteW.restype = wintypes.BOOL
    _advapi32.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                      wintypes.DWORD]
    _advapi32.CredDeleteW.restype = wintypes.BOOL
    _advapi32.CredFree.argtypes = [ctypes.c_void_p]

    def store_credentials(client_id, client_secret):
        client_id, client_secret = _validate(client_id, client_secret)
        RedactionFilter.add_secret(client_secret)
        blob = client_secret.encode("utf-16-le")
        buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        cred = _CREDENTIAL()
        cred.Flags = 0
        cred.Type = _CRED_TYPE_GENERIC
        cred.TargetName = SERVICE
        cred.Comment = "NinjaOne local connector (monitoring scope, read-only)"
        cred.CredentialBlobSize = len(blob)
        cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
        cred.Persist = _CRED_PERSIST_LOCAL_MACHINE
        cred.AttributeCount = 0
        cred.Attributes = None
        cred.UserName = client_id
        if not _advapi32.CredWriteW(ctypes.byref(cred), 0):
            raise CredentialStoreError(
                "Credential Manager write failed (winerror %d)"
                % ctypes.get_last_error())

    def _read():
        pcred = _PCREDENTIAL()
        if not _advapi32.CredReadW(SERVICE, _CRED_TYPE_GENERIC, 0,
                                   ctypes.byref(pcred)):
            raise CredentialStoreError(
                "NinjaOne credentials not found in Credential Manager (target "
                "'%s'). Run setup in PowerShell." % SERVICE)
        try:
            cred = pcred.contents
            client_id = cred.UserName or ""
            size = int(cred.CredentialBlobSize)
            # CRED_MAX_CREDENTIAL_BLOB_SIZE is 5*512. A blob written by another
            # tool under the same target name could be any size or shape, and
            # a NULL pointer with a nonzero size would be an access violation
            # rather than a Python exception — so validate before indexing.
            if size < 0 or size > _MAX_BLOB_BYTES:
                raise CredentialStoreError(
                    "The Credential Manager item for '%s' has an implausible "
                    "secret size (%d bytes). Re-run setup." % (SERVICE, size))
            if size % 2:
                raise CredentialStoreError(
                    "The Credential Manager item for '%s' is not valid UTF-16. "
                    "It was probably written by another tool. Re-run setup."
                    % SERVICE)
            if not cred.CredentialBlob:
                raise CredentialStoreError(
                    "The Credential Manager item for '%s' has no secret. "
                    "Re-run setup." % SERVICE)
            raw = ctypes.string_at(cred.CredentialBlob, size)
            try:
                client_secret = raw.decode("utf-16-le")
            except UnicodeDecodeError:
                # Deliberately does NOT echo the bytes: this message reaches
                # the log, and the bytes are credential material.
                raise CredentialStoreError(
                    "The Credential Manager item for '%s' could not be decoded "
                    "as UTF-16. Re-run setup." % SERVICE)
        finally:
            _advapi32.CredFree(pcred)
        if not client_id:
            raise CredentialStoreError(
                "The Credential Manager item for '%s' has no Client ID in its "
                "user name field. Re-run setup to store the credential pair."
                % SERVICE)
        return client_id, client_secret

    def get_credentials():
        client_id, client_secret = _read()
        RedactionFilter.add_secret(client_secret)
        # The gate runs on store; run it on read too. A value placed under
        # this target name by anything else flows straight into the OAuth
        # POST body otherwise.
        return _validate(client_id, client_secret)

    def has_credentials():
        pcred = _PCREDENTIAL()
        if _advapi32.CredReadW(SERVICE, _CRED_TYPE_GENERIC, 0,
                               ctypes.byref(pcred)):
            _advapi32.CredFree(pcred)
            return True
        return False

    def delete_credentials():
        return bool(_advapi32.CredDeleteW(SERVICE, _CRED_TYPE_GENERIC, 0))


# ===========================================================================
# macOS backend: login Keychain via /usr/bin/security
# ===========================================================================

else:
    SECURITY = "/usr/bin/security"

    # `security find-generic-password` prints attributes; the account lands in
    # a line shaped like:  "acct"<blob>="0a1b2c..."
    _ACCT_RE = re.compile(r'"acct"<blob>="([^"]*)"')

    def store_credentials(client_id, client_secret):
        client_id, client_secret = _validate(client_id, client_secret)
        RedactionFilter.add_secret(client_secret)
        # `security -i` reads the command from stdin, so neither value appears
        # in a process listing. -T whitelists /usr/bin/security for unattended
        # reads.
        command = (f'add-generic-password -U -s "{SERVICE}" -a "{client_id}" '
                   f'-T "{SECURITY}" -w "{client_secret}"\n')
        result = subprocess.run([SECURITY, "-i"], input=command,
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise CredentialStoreError(
                f"Keychain write failed: {redact(result.stderr.strip())}")

    def get_credentials():
        attrs = subprocess.run(
            [SECURITY, "find-generic-password", "-s", SERVICE],
            capture_output=True, text=True)
        if attrs.returncode != 0:
            raise CredentialStoreError(
                "NinjaOne credentials not found in the Keychain (service "
                "'ninjaone-connector'). Run setup in Terminal.")
        match = _ACCT_RE.search(attrs.stdout)
        client_id = match.group(1) if match else ""
        if not client_id:
            raise CredentialStoreError(
                "The Keychain item for 'ninjaone-connector' has no Client ID in "
                "its account field. Re-run setup to store the credential pair.")
        secret_result = subprocess.run(
            [SECURITY, "find-generic-password", "-s", SERVICE, "-w"],
            capture_output=True, text=True)
        if secret_result.returncode != 0:
            raise CredentialStoreError(
                "Could not read the Client Secret from the Keychain. If macOS "
                "asked for permission, choose Always Allow, then retry.")
        client_secret = secret_result.stdout.strip()
        RedactionFilter.add_secret(client_secret)
        return client_id, client_secret

    def has_credentials():
        result = subprocess.run(
            [SECURITY, "find-generic-password", "-s", SERVICE],
            capture_output=True, text=True)
        return result.returncode == 0

    def delete_credentials():
        subprocess.run([SECURITY, "delete-generic-password", "-s", SERVICE],
                       capture_output=True, text=True)
        return True
