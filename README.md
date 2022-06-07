
## 工程化实践

国内第一个基于 spring-authorization-server 的工程化实践， 扩展了 密码模式、短信登录

> https://github.com/pig-mesh/pig


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
--data-urlencode 'code=O9gGDaU87wnMVLM0dLNxxNTnE4In757BVBE_yJuG98BlG3T3rI_sluCLpEAThoxYTtRtmbhiGufiuFVc6FTtP3GhzFcObCMr5N_dqGuC3ChpZEvMJhrhqQ7dEqjMsuf5' \
--data-urlencode 'redirect_uri=https://pig4cloud.com'
```
## 刷新令牌

```shell
curl --location --request POST 'http://localhost:3000/oauth2/token' \
--header 'Authorization: Basic cGlnOnBpZw==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=ku4R4n7YD1f584KXj4k_3GP9o-HbdY-PDIIh-twPVJTmvHa5mLIoifaNhbBvFNBbse6_wAMcRoOWuVs9qeBWpxQ5zIFrF1A4g1Q7LhVAfH1vo9Uc7WL3SP3u82j0XU5x' \
```

## 撤销令牌

- 通过 access_token
```shell
curl --location --request POST 'http://localhost:3000/oauth2/revoke' \
--header 'Authorization: Basic cGlnOnBpZw==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'token=eyJraWQiOiI0NmM3Zjk0OS01NmZmLTRlMjgtYmI4Zi0wNjZjYWU4ODllNDkiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJsZW5nbGVuZyIsImF1ZCI6InBpZyIsIm5iZiI6MTYyOTM0MzM4NiwiZXhwIjoxNjI5MzQzNjg2LCJpYXQiOjE2MjkzNDMzODZ9.avRZ9NuybP8bqenEstvDq3SAKuSI6Y3ihh2PqeiQvwkUAWBPY6N9JCaxJllKhrcS6OgL76I38Yvt0B1ICMFistqemWl1rxQUB2aXpZuTwnPjxtxV6deDxyr--Y1w7I9jVpT5jnaqOXDIZ6dhIlUCfqBPT9a4DmwuEsz5H60KUO-NbMM66DPDxvTgauuylhrjiPQgaDyaxFHbtdw6qq_pgFI023fkIASodauCFiUcl64HKV3or9B3OkXW0EgnA553ofTbgz0hlROMfee15wuzOAXTUkhlUOjjosuEslimT9vFM9wtRza4o864Gi_j_zIhIoSSmRfUScXTgt9aZT1xlQ' \
--data-urlencode 'token_type_hint=access_token'
```

- 通过 refresh_token
```shell
curl --location --request POST 'http://localhost:3000/oauth2/revoke' \
--header 'Authorization: Basic cGlnOnBpZw==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'token=ku4R4n7YD1f584KXj4k_3GP9o-HbdY-PDIIh-twPVJTmvHa5mLIoifaNhbBvFNBbse6_wAMcRoOWuVs9qeBWpxQ5zIFrF1A4g1Q7LhVAfH1vo9Uc7WL3SP3u82j0XU5x' \
--data-urlencode 'token_type_hint=refresh_token'
```
