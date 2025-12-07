

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from src.users.router import admin_router
from src.auth.router import router as auth_router
from src.dependencies import limiter


# from slowapi import _rate_limit_exceeded_handler
# from slowapi.errors import RateLimitExceeded
# from src.dependencies import limiter

app = FastAPI()
# app.state.limiter = limiter
# app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler) #type: ignore
# 1. GZip (если используется)
# app.add_middleware(GZipMiddleware)

# 2. TrustedHost
# app.add_middleware(TrustedHostMiddleware)

# 3. CORS (ОБЯЗАТЕЛЬНО до ваших кастомных middleware)
app.add_middleware(CORSMiddleware)




@app.get("/" or "/home")
async def root(request: Request):
    return JSONResponse({"message": "Hello World! This is fastapi project"})

app.include_router(auth_router)
app.include_router(admin_router)
# app.include_router(menu_router)
# app.include_router(blog_router)