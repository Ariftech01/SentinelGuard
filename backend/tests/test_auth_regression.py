"""Regression coverage for session authentication endpoints."""
import os
from datetime import datetime, timedelta, timezone

import pytest
import requests
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://runtime-protection.preview.emergentagent.com").rstrip("/")


@pytest.fixture
def seeded_token():
    import asyncio
    token = "TEST_auth_regression_token"
    user_id = "TEST_auth_regression_user"

    async def seed():
        client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        db = client[os.environ["DB_NAME"]]
        await db.users.delete_many({"user_id": user_id})
        await db.user_sessions.delete_many({"session_token": {"$in": [token, "TEST_expired_token"]}})
        await db.users.insert_one({"user_id": user_id, "email": "TEST_auth@example.com", "name": "Auth Regression", "picture": ""})
        await db.user_sessions.insert_one({"user_id": user_id, "session_token": token, "expires_at": datetime.now(timezone.utc) + timedelta(days=7)})
        await db.user_sessions.insert_one({"user_id": user_id, "session_token": "TEST_expired_token", "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
        client.close()

    asyncio.run(seed())
    yield token

    async def cleanup():
        client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        db = client[os.environ["DB_NAME"]]
        await db.users.delete_many({"user_id": user_id})
        await db.user_sessions.delete_many({"session_token": {"$in": [token, "TEST_expired_token"]}})
        client.close()
    asyncio.run(cleanup())


def test_bearer_me_excludes_mongo_id(seeded_token):
    response = requests.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": f"Bearer {seeded_token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "TEST_auth@example.com"
    assert "_id" not in data


def test_expired_bearer_is_rejected(seeded_token):
    response = requests.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": "Bearer TEST_expired_token"})
    assert response.status_code == 401