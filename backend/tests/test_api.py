import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_auth_workflow(client: AsyncClient):
    # 1. Register a new user (becomes Admin as first user registered in test run)
    reg_res = await client.post(
        "/api/auth/register",
        json={"email": "tester@test.com", "password": "testpassword", "role": "Analyst"}
    )
    assert reg_res.status_code == 200
    reg_data = reg_res.json()
    assert reg_data["email"] == "tester@test.com"
    assert reg_data["role"] == "Admin" # First user registered auto-promoted to Admin

    # 2. Authenticate and obtain JWT
    login_res = await client.post(
        "/api/auth/login",
        data={"username": "tester@test.com", "password": "testpassword"}
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "access_token" in login_data
    token = login_data["access_token"]

    # 3. Access protected route with Bearer Token
    headers = {"Authorization": f"Bearer {token}"}
    me_res = await client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "tester@test.com"
