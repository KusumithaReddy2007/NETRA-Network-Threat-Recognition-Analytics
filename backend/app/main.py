from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import analytics
from app.routes import stream
from app.routes import threat
from app.routes import live


app = FastAPI(
    title="NETRA API",
    version="1.0.0",
    description="NETRA Passive AI-Based Network Threat Detection System",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(analytics.router)
app.include_router(stream.router)
app.include_router(threat.router)
app.include_router(live.router)


@app.get("/")
def root():
    return {
        "message": "NETRA Backend API Running",
        "status": "healthy",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
    }

