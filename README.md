# Apis to communicate with OAuth 1.0 servers
OAuth 1.0 is used by servers to grant third party applications access to their information.
The requests/responses comply to specifications at https://oauth.net/core/1.0a/
This sample provides you with 2 apis to ease the communication with OAuth servers.

Currently, Oauth 2.0 is the most commonly used and the most recent version.
The current sample provides apis only for OAuth 1.0.

## Prerequisities
- Genero Business Language 3.10

## Usage
There are 2 apis, you can call in your application:
```
DoAuth1Request(method, url, queryString, data, user_key, token_key)
```
To send requests to OAuth servers
```
ParseOAuth1RequestTokenResponse(ret)
```
To parse the OAuth server response.

Feel free to adapt the apis to the servers needs.