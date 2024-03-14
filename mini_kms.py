"""A Mini KMS server using Askar for key management."""

from contextlib import asynccontextmanager
from hashlib import sha256
import json
import logging
from typing import cast

from aries_askar import Key, KeyAlg, Store
import base58
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import Base64UrlBytes, BaseModel
from pydantic.types import Base64UrlEncoder


LOGGER = logging.getLogger(__name__)


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

    alg: KeyAlg


class GenerateKeyResp(BaseModel):
    """Generated key response."""

    kid: str
    jwk: dict
    b58: str

    @classmethod
    def from_key(cls, kid: str, key: Key) -> "GenerateKeyResp":
        """Create a response from a key."""
        b58 = base58.b58encode(key.get_public_bytes()).decode("utf-8")
        jwk = json.loads(key.get_jwk_public())
        return cls(kid=kid, jwk=jwk, b58=b58)


def derive_kid(key: Key) -> str:
    """Derive a kid from a key."""
    return sha256(key.get_public_bytes()).digest().hex()[:7]


@app.post("/key/generate")
async def generate_key(
    req: GenerateKeyReq, store: Store = Depends(store)
) -> GenerateKeyResp:
    """Generate a key and store it."""
    key = Key.generate(req.alg)
    kid = derive_kid(key)
    async with store.session() as txn:
        await txn.insert_key(kid, key)
    return GenerateKeyResp.from_key(kid, key)


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

    return GenerateKeyResp.from_key(kid, key)


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
