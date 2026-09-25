/**
 * What `ApiKeyProvider.generate()` makes: `<prefix>_<id>_<secret>`, a
 * lowercase prefix of 1-16 characters, 64 random bits of public id in hex,
 * and 256 random bits of secret in base64url. It has no dot, so no JWT (whose
 * compact form has two) ever matches it, and `JwtBearerProvider` leaves it
 * to the API key provider, whatever order the two run in.
 */
export const API_KEY_PATTERN = /^([a-z][a-z0-9]{0,15})_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;

/** What a prefix may be: the first group of {@link API_KEY_PATTERN}. */
export const API_KEY_PREFIX_PATTERN = /^[a-z][a-z0-9]{0,15}$/;
