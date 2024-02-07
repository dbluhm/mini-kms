"""A Mini KMS server using Askar for key management."""

from contextlib import asynccontextmanager
import json
from typing import cast
from fastapi import Depends, FastAPI, HTTPException, status
from aries_askar import Store, Key, KeyAlg
from pydantic import BaseModel, Base64UrlBytes
from pydantic.types import Base64UrlEncoder


@asynccontextmanager
async def setup_store(app: FastAPI):
    """Setup the Askar store."""
    key = Store.generate_raw_key()
    store = await Store.provision("sqlite://:memory:", "raw", key, profile="mini")
    app.state.store = store
    try:
        yield
    finally:
        await store.close()


app = FastAPI(lifespan=setup_store)


async def store():
    """Get the store from the app state."""
    yield app.state.store


class GenerateKeyReq(BaseModel):
    """Generate key request."""

    kid: str
    alg: KeyAlg


class GenerateKeyResp(BaseModel):
    """Generated key response."""

    kid: str
    jwk: dict


@app.post("/key/generate")
async def generate_key(
    req: GenerateKeyReq, store: Store = Depends(store)
) -> GenerateKeyResp:
    """Generate a key and store it."""
    key = Key.generate(req.alg)
    async with store.session() as txn:
        await txn.insert_key(req.kid, key)
    return GenerateKeyResp(kid=req.kid, jwk=json.loads(key.get_jwk_public()))


@app.get("/key/{kid}")
async def get_key(kid: str, store: Store = Depends(store)) -> GenerateKeyResp:
    """Get a key by its kid."""
    async with store.session() as txn:
        key_entry = await txn.fetch_key(kid)

    if key_entry:
        key = cast(Key, key_entry.key)
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Key not found"
        )

    return GenerateKeyResp(kid=kid, jwk=json.loads(key.get_jwk_public()))


@app.delete("/key/{kid}")
async def delete_key(kid: str, store: Store = Depends(store)):
    """Delete a key by its kid."""
    async with store.session() as txn:
        await txn.remove_key(kid)
    return {"message": "Key deleted"}


class SigReq(BaseModel):
    """KID and Message to be signed in base64url encoding."""

    kid: str
    data: Base64UrlBytes


class SigResp(BaseModel):
    """Signed message in base64url encoding."""

    sig: Base64UrlBytes


@app.post("/sign")
async def sign(req: SigReq, store: Store = Depends(store)) -> SigResp:
    """Sign a message with a key."""
    async with store.session() as txn:
        key_entry = await txn.fetch_key(req.kid)
    if key_entry:
        key = cast(Key, key_entry.key)
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Key not found"
        )

    sig = key.sign_message(req.data)
    return SigResp(sig=Base64UrlEncoder.encode(sig))
