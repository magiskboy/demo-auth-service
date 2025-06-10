#!/usr/bin/env python3
"""
Script to set up test database for OAuth2 service tests.

This script creates the test database if it doesn't exist.
Make sure PostgreSQL is running before executing this script.
"""

import asyncio
import asyncpg
import sys
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from sqlmodel import SQLModel

# Import all models to ensure they're registered with SQLModel
from app.users.models import User, LinkedAccount  # noqa
from app.rbac.models import Role, Permission, UserRole, RolePermission  # noqa

# Database configuration
DB_USER = "postgres"
DB_PASSWORD = "postgres"
DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "test_oauth2_service"

# Connection URLs
ADMIN_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/postgres"
TEST_DATABASE_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


async def create_test_database():
    """Create the test database if it doesn't exist."""
    try:
        # Connect to PostgreSQL admin database
        conn = await asyncpg.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            database="postgres"
        )
        
        # Check if test database exists
        db_exists = await conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", DB_NAME
        )
        
        if not db_exists:
            # Create the test database
            await conn.execute(f'CREATE DATABASE "{DB_NAME}"')
            print(f"✅ Created test database: {DB_NAME}")
        else:
            print(f"✅ Test database already exists: {DB_NAME}")
        
        await conn.close()
        
    except Exception as e:
        print(f"❌ Failed to create test database: {e}")
        sys.exit(1)


async def verify_connection():
    """Verify we can connect to the test database."""
    try:
        engine = create_async_engine(TEST_DATABASE_URL)
        
        async with engine.begin() as conn:
            # Test basic connection
            result = await conn.execute(text("SELECT 1"))
            assert result.scalar() == 1
            
            # Create and drop a test table to verify permissions
            await conn.run_sync(SQLModel.metadata.create_all)
            print("✅ Successfully created all tables")
            
            await conn.run_sync(SQLModel.metadata.drop_all)
            print("✅ Successfully dropped all tables")
        
        await engine.dispose()
        print("✅ Database connection and permissions verified")
        
    except Exception as e:
        print(f"❌ Failed to verify database connection: {e}")
        sys.exit(1)


async def main():
    """Main setup function."""
    print("🔧 Setting up test database for OAuth2 service...")
    print(f"📍 Database: {DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"👤 User: {DB_USER}")
    print()
    
    await create_test_database()
    await verify_connection()
    
    print()
    print("🎉 Test database setup complete!")
    print(f"🔗 Test database URL: {TEST_DATABASE_URL}")
    print()
    print("You can now run tests with:")
    print("  pytest tests/")
    print()
    print("Or run specific test groups:")
    print("  pytest tests/ -m 'unit'      # Unit tests only")
    print("  pytest tests/ -m 'db'        # Database tests only")
    print("  pytest tests/ -m 'rbac'      # RBAC tests only")


if __name__ == "__main__":
    asyncio.run(main()) 