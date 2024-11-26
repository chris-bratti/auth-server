# API Endpoints

There are only two endpoints in the application. The `/auth` is the main authentication endpoint

## Auth
Endpoint to handle all auth requests. Use the `X-Request-Type` header to indicate the type of auth request

### Sign Up
**Creates a new user and emails a `verification_token` to their provided email**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: signup
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json

{
    "username": "testuser",
    "data":{
        "first_name": "Test",
        "last_name": "User",
        "email": "testuser@example.com",
        "new_password_request":{
            "password": "Password1234!",
            "confirm_password": "Password1234!"
        }
    }
}
```
Response
```
{
    "success": true,
    "message": "New user enrolled",
    "response": null
}
```

### Login
**Logs user in**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: login
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json

{
    "username": "testuser",
    "data":{
        "password": "Password1234!"
    }
}
```
Response
```
{
    "success": false,
    "message": "User has 2FA enabled",
    "response": {
        "two_factor_enabled": true,
        "login_token": "logintoken"
    }
}
```
- `two_factor_enabled` specifies if the user has 2 factor auth enabled
- `login_token` is the JWT-based token to pass to the `verify_top` request to complete login (if user enabled 2fa)

### Verify User
**Verifies a user given a `verification_token`**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: verify_user
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json

{
    "username": "testuser",
    "data": {
        "verification_token": "verifcationtoken"
    }
}
```
- `verification_token` is the token emailed to the user

Response
```
{
    "success": true,
    "message": "User verified",
    "response": null
}
```

### Request Reset Password
**Makes a password reset token and sends it to the user's email**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: request_password_reset
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json
Content-Length: 30

{
    "username": "testuser"
}
```
Response
```
{
    "success": true,
    "message": "Password reset request successful",
    "response": null
}
```
### Reset Password
**Resets a password given a password reset token**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: reset_password
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json

{
    "username": "testuser",
    "data":{
        "reset_token": "reset_token",
        "new_password_request" : {
            "password": "NewPass1234!",
            "confirm_password": "NewPass1234!"
        }
    }
}
```
- `reset_token` is the token emailed to the user

Response
```
{
    "success": true,
    "message": "Password reset successful",
    "response": null
}
```
### Change Password
**Updates a user password given their current password**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: change_password
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json

{
    "username": "testuser",
    "data":{
        "current_password": "Password1234!",
        "new_password_request" : {
            "password": "NewPass1234!",
            "confirm_password": "NewPass1234!"
        }
    }
}
```
Response
```
{
    "success": true,
    "message": "Password change successful",
    "response": null
}
```

### Generate 2FA
**Generates a 2FA code for user to enroll their device**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: generate_2fa
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json

{
    "username": "testuser"
}
```
Response
```
{
    "qr_code": "base64encodedPNG==",
    "token": "generatedtoken",
    "enable_2fa_token": "generatedtoken"
}
```
- `qr_code` is a base64 encoded QR code that a user can use to enroll their device
- `token` is the 2FA token for the user
- `enabled_2fa_token` is a JWT-based token to pass to the `enable_2fa` call to enable 2FA

### Enable 2FA
**Enables 2FA for a user given a `enable_2fa_token` JWT**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: enable_2fa
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json

{
    "username": "testuser",
    "data":{
        "two_factor_token": "randomgeneratedtoken",
        "otp": "1111",
        "enable_2fa_token": "randomgeneratedtoken"
    } 
}
```
- `two_factor_token` is the `token` from the `generate_2fa` call
- `enable_2fa_token` is the `enable_2fa_token` JWT from the `generate_2fa` call
- `otp` is the user provided One Time Password from their 2FA service to validate they were enrolled correctly

Response
```
{
    "success": true,
    "message": "2FA enabled",
    "response": null
}
```

### Verify OTP
**Verifies the 2FA TOTP token provided by a user and logs user in to session**

Request
```
POST /auth HTTP/1.1
Host: localhost:8080
X-Request-Type: verify_otp
X-App-Name: demo_app
X-Api-Key: generated-api-key
Content-Type: application/json

{
    "username": "testuser",
    "data":{
        "otp": "1111",
        "login_token": "randomgeneratedtoken"
    }
}
```
- `otp` is the user-provided TOTP code from their 2FA app
- `login_token` is the `login_token` JWT from the `login` call

Response
```
{
    "success": true,
    "message": "OTP was successful",
    "response": null
}
```

## Internal

Internal routes for admin use, use the `X-Admin-Key` header to authenticate against the `ADMIN_KEY` passed in during server start

### Reload keys
**Internal endpoint to refresh API key cache**

Request
```
POST /internal/reload-keys HTTP/1.1
Host: localhost:8080
X-Admin-Key: examplepassword
```
Response
```
"API keys reloaded"
```