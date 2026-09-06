from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import threat
from app.routes import stream
from app.routes import analytics


# Create FastAPI application
app = FastAPI(
    title="NETRA API",
    version="1.0.0",
    description="Network Threat Recognition and Analytics Platform"
)


# Allow React frontend to communicate with FastAPI backend
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


# Include API routes
app.include_router(threat.router)
app.include_router(stream.router)
app.include_router(analytics.router)


# Root endpoint
@app.get("/")
def root():
    return {
        "message": "NETRA API is running"
    }


# Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }