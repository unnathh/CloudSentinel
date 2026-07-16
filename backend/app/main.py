import logging
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models.user import User
from app.models.account import AWSAccount
from app.services.auth_service import get_password_hash
from app.models.scan import ScanResult

# Import routers
from app.api.auth import router as auth_router
from app.api.accounts import router as accounts_router
from app.api.findings import router as findings_router
from app.api.graph import router as graph_router
from app.api.resources import router as resources_router
from app.api.reports import router as reports_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cloudsentinel.main")

async def init_db_and_seed():
    """Initializes tables and seeds basic demo accounts."""
    logger.info("Initializing database tables...")
    async with engine.begin() as conn:
        # Create all tables if they don't exist
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("Checking seed data...")
    async with SessionLocal() as db:
        # 1. Seed users
        admin_check = await db.execute(select(User).where(User.email == "admin@cloudsentinel.local"))
        if not admin_check.scalars().first():
            logger.info("Seeding system accounts...")
            admin = User(
                email="admin@cloudsentinel.local",
                password_hash=get_password_hash("adminpassword"),
                role="Admin"
            )
            analyst = User(
                email="analyst@cloudsentinel.local",
                password_hash=get_password_hash("analystpassword"),
                role="Analyst"
            )
            viewer = User(
                email="viewer@cloudsentinel.local",
                password_hash=get_password_hash("viewerpassword"),
                role="Viewer"
            )
            db.add_all([admin, analyst, viewer])

        # 2. Seed demo account
        acct_check = await db.execute(select(AWSAccount).where(AWSAccount.name == "demo-aws-account"))
        if not acct_check.scalars().first():
            logger.info("Seeding demo AWS account configuration...")
            demo_acct = AWSAccount(
                name="demo-aws-account",
                account_id="123456789012",
                auth_type="keys",
                region="us-east-1"
            )
            db.add(demo_acct)
            
        # 3. Clean up stale scans (stuck in 'running')
        stuck_scans_stmt = select(ScanResult).where(ScanResult.status == "running")
        stuck_scans_res = await db.execute(stuck_scans_stmt)
        stuck_scans = stuck_scans_res.scalars().all()
        for ss in stuck_scans:
            logger.info(f"Resetting stuck scan ID {ss.id} status to 'failed'")
            ss.status = "failed"
            ss.completed_at = datetime.utcnow()

        await db.commit()
    logger.info("Database setup finished successfully.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    await init_db_and_seed()
    yield
    # Shutdown tasks (if any)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise-grade Cloud Security Posture Management (CSPM) API platform",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for React frontend client
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Scope to specific URLs in production (e.g. http://localhost:5173)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(accounts_router, prefix=settings.API_V1_STR)
app.include_router(findings_router, prefix=settings.API_V1_STR)
app.include_router(graph_router, prefix=settings.API_V1_STR)
app.include_router(resources_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)

@app.get("/")
async def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API portal.",
        "documentation": "/docs"
    }
