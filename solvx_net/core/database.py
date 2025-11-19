"""Database setup and session management."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
from typing import Generator

from solvx_net.core.config import get_config
from solvx_net.core.logging import get_logger

logger = get_logger(__name__)


class Base(DeclarativeBase):
    """Base class for all database models."""

    pass


# Global engine and session factory
_engine = None
_SessionLocal = None


def init_database(db_url: str = None, echo: bool = False) -> None:
    """
    Initialize database engine and session factory.

    Args:
        db_url: Database URL (uses config default if None)
        echo: Whether to echo SQL queries
    """
    global _engine, _SessionLocal

    config = get_config()
    db_url = db_url or config.database.url

    # Expand user home directory in SQLite URLs
    if db_url.startswith("sqlite:///~/"):
        from pathlib import Path

        db_path = Path(db_url.replace("sqlite:///~/", "")).expanduser()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite:///{db_path}"

    logger.info(f"Initializing database: {db_url}")

    # Special handling for SQLite
    if db_url.startswith("sqlite"):
        _engine = create_engine(
            db_url,
            echo=echo or config.database.echo,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    else:
        _engine = create_engine(
            db_url,
            echo=echo or config.database.echo,
        )

    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


def get_engine():
    """Get database engine."""
    if _engine is None:
        init_database()
    return _engine


def get_session_factory():
    """Get session factory."""
    if _SessionLocal is None:
        init_database()
    return _SessionLocal


@contextmanager
def get_db() -> Generator:
    """
    Database session context manager.

    Usage:
        with get_db() as db:
            db.query(Device).all()
    """
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def create_tables() -> None:
    """Create all database tables."""
    from solvx_net.core.models import (
        Device,
        Capture,
        Flow,
        Alert,
        ThreatScoreSnapshot,
        Rule,
        ARPEntry,
    )

    engine = get_engine()
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


def drop_tables() -> None:
    """Drop all database tables (use with caution!)."""
    engine = get_engine()
    logger.warning("Dropping all database tables...")
    Base.metadata.drop_all(bind=engine)
    logger.info("Database tables dropped")
