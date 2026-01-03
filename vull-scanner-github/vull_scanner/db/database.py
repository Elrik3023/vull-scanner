"""Database connection and session management."""

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from vull_scanner.db.models import Base


# Default to SQLite for development, use PostgreSQL in production
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./vull_scanner.db"
)

# Handle PostgreSQL URLs from some cloud providers
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Create engine with appropriate settings
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},  # Required for SQLite
        echo=os.environ.get("SQL_DEBUG", "").lower() == "true",
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,  # Verify connections before use
        echo=os.environ.get("SQL_DEBUG", "").lower() == "true",
    )

# Create session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# Type alias for sessions
DatabaseSession = Session


def init_db() -> None:
    """Initialize the database by creating all tables.

    This should be called on application startup.
    """
    Base.metadata.create_all(bind=engine)


def close_db() -> None:
    """Close the database connection.

    This should be called on application shutdown.
    """
    engine.dispose()


def get_db() -> Generator[Session, None, None]:
    """Get a database session.

    This is a dependency injection function for FastAPI.

    Yields:
        Database session.

    Example:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Get a database session as a context manager.

    For use outside of FastAPI dependency injection.

    Yields:
        Database session.

    Example:
        with get_db_context() as db:
            scan = db.query(Scan).first()
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
