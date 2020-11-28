# ProtonVPNEncryption
Reverse engineered protonvpn auth data encryption

### Use as:
1. Do post request
   URL: https://api.protonvpn.ch/auth/info
   Headers:
       x-pm-appversion: WebVPNSettings_4.1.19
       x-pm-apiversion: 3
       x-pm-locale: en
       Accept: application/vnd.protonmail.v1+json
       Content-Type: application/json; charset=UTF-8
   Data: {"Username":"here your username"}
2. Parse needed data
3. Do post request
   URL: http://127.0.0.1:6522/encrypt
   Data: {"username":"username", "password":"password", "modulus":"modulus", "ServerEphemeral":"ServerEphemeral", "salt":"salt"}
4. In a response you could get needed auth data
