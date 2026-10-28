from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uuid
import subprocess
import db

app = FastAPI(title="xieyimianban 面板后端")

# ⚠️ 记得这里改成你节点机的真实 IP
NODE_IP = "1.2.3.4" 
XRAY_API_PORT = "10085"

@app.on_event("startup")
def startup():
    db.init_db()

class UserCreate(BaseModel):
    email: str
    protocol: str = "vless"

@app.post("/api/create")
def create_node(user: UserCreate):
    new_uuid = str(uuid.uuid4())
    
    if not db.add_user_to_db(user.email, new_uuid, user.protocol):
        raise HTTPException(status_code=400, detail="用户已存在")

    if user.protocol == "vless":
        cmd = [
            "xray", "api", "adi",
            f"--server={NODE_IP}:{XRAY_API_PORT}",
            f'inbounds[0].settings.clients=[{{"id":"{new_uuid}", "email":"{user.email}"}}]'
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            return {"status": "success", "uuid": new_uuid}
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"API 报错: {e.stderr}")
    
    return {"status": "pending"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
