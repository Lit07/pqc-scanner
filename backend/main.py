from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from db.database import create_tables
from backend.routes import health, scan, results, assets, cbom, risk, pqc, ai
from config.logging_config import configure_logging
from utils.logger import get_logger

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("PQC Scanner starting up...")
    create_tables()
    logger.info("Database tables created/verified")
    yield
    logger.info("PQC Scanner shutting down...")


app = FastAPI(
    title="PQC Scanner API",
    description=(
        "Post-Quantum Cryptography Scanner — "
        "Scans TLS endpoints for quantum vulnerability, "
        "generates CBOM, risk scoring, PQC migration plans, "
        "and AI-powered security analysis."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")
app.include_router(results.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(cbom.router, prefix="/api/v1")
app.include_router(risk.router, prefix="/api/v1")
app.include_router(pqc.router, prefix="/api/v1")
app.include_router(ai.router, prefix="/api/v1")


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "Resource not found", "path": str(request.url)}
    )


@app.exception_handler(422)
async def validation_error_handler(request: Request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation error", "errors": str(exc)}
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


@app.get("/")
def root():
    return {
        "service": "PQC Scanner",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health"
    }
