from fastapi import FastAPI, Depends
import redis
from auth import create_access_token, verify_token

app = FastAPI(title="FastAPI Security Audit Demo")

# Internal Redis dependency
redis_client = redis.Redis(host="redis", port=6379, decode_responses=True)

@app.get("/")
def root():
    return {"status": "ok"}

@app.post("/login")
def login(username: str):
    token = create_access_token(username)
    redis_client.set(f"session:{username}", token, ex=3600)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/profile")
def profile(payload: dict = Depends(verify_token)):
    return {"message": "authenticated", "user": payload}

@app.get("/health")
def health():
    try:
        pong = redis_client.ping()
        return {"app": "up", "redis": pong}
    except Exception as exc:
        return {"app": "up", "redis": "down", "error": str(exc)}
