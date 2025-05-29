# API Info

---

## [`http://localhost:3001/api/register`](http://localhost:3001/api/register)

<details>
<summary>`POST`</summary>

#### Header

```
Content-Type: application/json
```

#### Data

```json
{
    "name": "<name>",
    "email": "<email>",
    "mobile": "<mob>",
    "password": "<password>",
    "role": "<PhotoGrapher|Hirer>"
}
```

#### Response on success

```json
{ "success": true, "msg": "Register Successful" }
```

#### Response on failed

```json
{ "success": false, "msg": "...." }
```

#### Example

```bash
curl -X POST http://localhost:3001/api/register \
    -H "Content-Type: application/json" \
    -d '{
            "name": "<name>",
            "email": "<email>",
            "mobile": "<mob>",
            "password": "<password>",
            "role": "PhotoGrapher"
        }'
```

<details>

---
