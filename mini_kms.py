"""A Mini KMS server using Askar for key management."""

from contextlib import asynccontextmanager
import json
import logging
from typing import cast

from aries_askar import Key, KeyAlg, Store
import base58
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import Base64UrlBytes, BaseModel, Field
from pydantic.types import Base64UrlEncoder


LOGGER = logging.getLogger("uvicorn.error." + __name__)


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


app = FastAPI(
    lifespan=setup_store,
    title="Mini KMS",
    summary="A lightweight service for secure key management using Aries Askar",
    version="0.1.0",
)


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
    return key.get_jwk_thumbprint()


@app.post("/key/generate", tags=["kms"], response_description="The generated key")
async def generate_key(
    req: GenerateKeyReq, store: Store = Depends(store)
) -> GenerateKeyResp:
    """Generate a key and store it."""
    key = Key.generate(req.alg)
    kid = derive_kid(key)
    async with store.session() as txn:
        await txn.insert_key(kid, key)
    return GenerateKeyResp.from_key(kid, key)


class AssociateKeyReq(BaseModel):
    """Associate Key Request body."""

    wallet_id: str
    key_uri: str = Field(
        examples=["did:example:1234#key-1"],
        pattern=r"did:([a-z0-9]+):((?:[a-zA-Z0-9._%-]*:)*[a-zA-Z0-9._%-]+)#.*",
    )


class AssociateKeyResp(BaseModel):
    """Associate Key Response body."""

    wallet_id: str
    key_uri: str
    kid: str


@app.post(
    "/key/{kid}/associate",
    tags=["kms"],
    response_description="Summary of associated identifiers",
)
async def associate_key(
    kid: str, req: AssociateKeyReq, store: Store = Depends(store)
) -> AssociateKeyResp:
    """Associate a key with identifiers."""
    LOGGER.debug(
        "Associating key %s with: wallet_id: %s, key_uri: %s",
        kid,
        req.wallet_id,
        req.key_uri,
    )
    async with store.transaction() as txn:
        entry = await txn.fetch_key(kid, for_update=True)
        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Key not found"
            )

        did = req.key_uri.split("#", 1)[0]
        await txn.update_key(
            kid,
            tags={
                "wallet_id": req.wallet_id,
                "key_uri": req.key_uri,
                "did": did,
            },
        )
        await txn.commit()

    return AssociateKeyResp(wallet_id=req.wallet_id, key_uri=req.key_uri, kid=kid)


@app.get("/key", tags=["kms"], response_description="Retrieved key")
async def get_key_by_identifiers(
    wallet_id: str, key_uri: str, store: Store = Depends(store)
) -> GenerateKeyResp:
    """Retrieve a key by identifiers wallet_id and key_uri."""
    LOGGER.debug("Retrieving key with: wallet_id: %s, key_uri: %s", wallet_id, key_uri)
    async with store.session() as txn:
        entries = await txn.fetch_all_keys(
            tag_filter={"wallet_id": wallet_id, "key_uri": key_uri}, limit=1
        )
        if not entries:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Key not found"
            )

        kid = cast(str, entries[0].name)
        key = cast(Key, entries[0].key)
        return GenerateKeyResp.from_key(kid, key)


@app.get("/key/{kid}", tags=["kms"], response_description="Retrieved key")
async def get_key(kid: str, store: Store = Depends(store)) -> GenerateKeyResp:
    """Get a key by its kid."""
    async with store.session() as txn:
        key_entry = await txn.fetch_key(kid)

    if key_entry:
        key = cast(Key, key_entry.key)
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    return GenerateKeyResp.from_key(kid, key)


@app.delete("/key/{kid}", tags=["kms"], response_description="Deleted kid")
async def delete_key(kid: str, store: Store = Depends(store)):
    """Delete a key by its kid."""
    async with store.session() as txn:
        await txn.remove_key(kid)
    return {"kid": kid}


class SigReq(BaseModel):
    """KID and Message to be signed in base64url encoding."""

    kid: str
    data: Base64UrlBytes


class SigResp(BaseModel):
    """Signed message in base64url encoding."""

    sig: Base64UrlBytes


@app.post(
    "/sign", tags=["kms"], response_description="Signed message in base64url encoding"
)
async def sign(req: SigReq, store: Store = Depends(store)) -> SigResp:
    """Sign a message with a key."""
    async with store.session() as txn:
        key_entry = await txn.fetch_key(req.kid)
    if key_entry:
        key = cast(Key, key_entry.key)
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    sig = key.sign_message(req.data)
    return SigResp(sig=Base64UrlEncoder.encode(sig))
