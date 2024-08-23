# OpenID Connect utility

This tool helps to obtain a JWT from an identity provider using either the _client credentials flow_ or the _authorization code flow_.

## Preparations

Copy the file [default.env](./default.env) to .env and put in the required values.

Or: copy [default.env](./default.env) to a new location and update the
values. Then set the environment variable `OIDC_ENVFILE` to the path of
the file.

## Usage

- `oidc-util authorization_code` or
- `oidc-util client_credentials`
