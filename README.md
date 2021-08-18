
## 授权码认证
```shell
'http://localhost:3000/oauth2/authorize?client_id=pig&client_secret=pig&response_type=code&redirect_uri=https://pig4cloud.com'
```

## 获取令牌

```shell
curl --location --request POST 'http://localhost:3000/oauth2/token' \
--header 'Authorization: Basic cGlnOnBpZw==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'code=1s58KX_IKMDA0Nr_gW3eVk8ytSh-6jynT-AJLC25IHxPCOLAqAZFV-usGUYP0FMwlxoFiddoEaB2i9zYW65vAJZoz9LVR_F60ywXA4McFfP_lJbv75Jg95xnN_CfHrtU' \
--data-urlencode 'redirect_uri=https://pig4cloud.com'
```
## 刷新令牌

```shell
curl --location --request POST 'http://localhost:3000/oauth2/token' \
--header 'Authorization: Basic cGlnOnBpZw==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token={refresh_token}' \
```

## 撤销令牌

- 通过 access_token
```shell
curl --location --request POST 'http://localhost:3000/oauth2/revoke' \
--header 'Authorization: Basic cGlnOnBpZw==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'token={access_token}' \
--data-urlencode 'token_type_hint=access_token'
```

- 通过 refresh_token
```shell
curl --location --request POST 'http://localhost:3000/oauth2/revoke' \
--header 'Authorization: Basic cGlnOnBpZw==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'token={refresh_token}' \
--data-urlencode 'token_type_hint=refresh_token'
```
