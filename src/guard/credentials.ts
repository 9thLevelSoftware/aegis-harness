/**
 * Private keys and credential stores, by name: what the shell rules refuse to print or copy and
 * the read rules refuse to read. Backslashes count as separators, for Windows paths.
 */

const PRIVATE_NAME = /(^|[\\/])(id_rsa|id_ed25519|id_ecdsa|id_dsa)$|\.(pem|key|p12|pfx)$|(^|[\\/])\.(netrc|git-credentials|pypirc)$|(^|[\\/])\.aws[\\/]credentials$|(^|[\\/])\.docker[\\/]config\.json$|(^|[\\/])\.kube[\\/]config$|(^|[\\/])gcloud[\\/](application_default_credentials\.json|credentials\.db|access_tokens\.db|legacy_credentials([\\/]|$))|(^|[\\/])\.azure[\\/](accessTokens\.json|msal_token_cache\.(json|bin))$/i;

/** Certificates and public keys that end in `.pem` by convention: `ca.pem`, `fullchain.pem`, `server-cert.pem`, `public.pem`. */
const PUBLIC_PEM = /(^|[\\/])((ca|cacert|ca-bundle|ca-certificates|cert|chain|fullchain|root|rootca|root-ca|intermediate|public|pubkey)\.pem|[^\\/]*[-_.](cert|crt|chain|ca|pub|public|pubkey)\.pem)$/i;

/** True when the name says the file holds a private key or credentials. */
export function isPrivateFile(path: string): boolean {
  return PRIVATE_NAME.test(path) && !PUBLIC_PEM.test(path);
}

/** True for a `.pem` named as a certificate or public key, which is safe to print. */
export function isPublicPem(path: string): boolean {
  return PUBLIC_PEM.test(path);
}

/** A home-relative path (`.ssh`, `.aws/config`) inside a directory that holds keys or tokens: copying or searching it whole exposes them. */
export function inCredentialStore(homeRel: string): boolean {
  return /^(\.(ssh|aws|gnupg|kube|azure)|\.config[\\/]gcloud)([\\/]|$)/i.test(homeRel);
}
