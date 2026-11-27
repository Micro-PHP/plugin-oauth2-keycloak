# Keycloak OAuth2 provider for Micro

Register `OAuth2ClientPlugin` and `OAuth2KeycloakProviderPlugin` in the application. Set `MICRO_OAUTH2_<NAME>_TYPE` to `keycloak` and `MICRO_OAUTH2_<NAME>_REALM` to the Keycloak realm. The provider uses that realm for authorization, token exchange, and userinfo.

## Signed userinfo

Plain JSON profiles work with the OAuth2 configuration alone. For a JSON response with a `jwt` field, configure the verification algorithm and key used by the realm. An RSA configuration can use a local PEM file.

```dotenv
SECURITY_TOKEN_PROVIDER_DEFAULT_ALGORITHM=RS256
SECURITY_TOKEN_PROVIDER_DEFAULT_PUBLIC=file:///run/secrets/keycloak-realm.pem
```

The adapter reads the same default-provider settings as Micro Security. `SECURITY_TOKEN_PROVIDER_DEFAULT_PUBLIC` takes precedence. With the default `HS256` algorithm, `SECURITY_TOKEN_PROVIDER_DEFAULT_SECRET` supplies the shared key when `PUBLIC` is empty. HS256 requires an explicitly configured secret of at least 32 bytes. Verification accepts inline keys and existing key files. Use a `file://` URI when a missing file must raise a configuration error.

Version 1.6 uses `firebase/php-jwt` 7.x for verification and continues to honor a registered `SecurityFacadeInterface`. Applications that explicitly require `micro/plugin-security` 1.0 need a compatible version of that package before they can use both, because 1.0 requires JWT 6.x.
