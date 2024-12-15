# API Endpoints

This API's only public endpoints are for the OAuth flow, all user authentication is done through the UI.

## Clients
Endpoints to handle OAuth client transactions

### Register Client
**Registers a new OAuth client and reloads client cache**

Request
```
POST /clients/register HTTP/1.1
Host: localhost:3000
X-Admin-Key: examplepassword
Content-Type: application/json

{
    "app_name": "Test App",
    "contact_email": "contact@app.com",
    "redirect_url" : "https://localhost:8080/test"
}

```
Response
```
{
    "success": true,
    "client_id": "client-id",
    "client_secret": "client-secret",
    "redirect_url": "https://localhost:8080/test"
}
```

## Token

OAuth endpoint to retrieve an `access_token` and `refresh_token` to make requests to the `/user` endpoint.

`access_tokens`, `refresh_tokens`, and `authorization_codes` are all **user-locked**, which means they are only valid for the username that gets bound to the `authorization_code` during the user login process.

The `Authorization` header requires a base64 encoded `client-id:client-secret` string

### Authorization code
**Gets an access_token and refresh_token given a valid client**

Request
```
POST /oauth/token HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Base64(client-id:client-secret)

grant_type=authorization_code&authorization_code=authorization-code

```
Response
```
{
    "success": true,
    "access_token": "JWT-access-token",
    "refresh_token": "refresh-token",
    "username": "user",
    "expiry": 1734285694
}
```
- `access_token` is a JWT token to be used in the Bearer header for the `/user` endpoints. Expires after 10 minutes
- `refresh_token` can be used to get a new `access_token` using the `refresh_token` `grant_type`. Expires after 30 days

### Refresh token
**Gets an `access_token` given a `refresh_token` and valid client header**

Request
```
POST /oauth/token HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Base64(client-id:client-secret)

grant_type=refresh_token&refresh_token=refresh-token
```

Response
```
{
    "success": true,
    "access_token": "JWT-access-token",
    "username": "user",
    "expiry": 1734285694
}
```
- `access_token` is a JWT token to be used for in the Bearer header for the user endpoints. Expires after 10 minutes

## User

Endpoints to request user data, requires valid `access_token`

### Info
**Gets user info**

Request
```
GET /user/info?username=user HTTP/1.1
Host: localhost:3000
Authorization: Bearer access-token
```
Response
```
{
    "success": true,
    "user_data": {
        "first_name": "Test",
        "last_name": "User",
        "username": "user",
        "two_factor": false,
        "verified": true,
        "email": "testuser@gmail.com"
    },
    "timestamp": 1734286255
}
```
- `two_factor` is a bool field indicating if the user has 2fa enabled for their account
- `verified` is a bool field indicating if the user has verified their account

## Internal

### Reload OAuth clients
**Internal endpoint to load OAuth clients from DB into Redis cache**

Request
```
POST /internal/reload-clients HTTP/1.1
Host: localhost:3000
X-Admin-Key: examplepassword
```
Response
```
{
    "success": true,
    "clients_loaded": 1
}
```
- `clients_loaded` indicates how many clients were loaded from the DB