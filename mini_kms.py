"""A Mini KMS server using Askar for key management."""

from contextlib import asynccontextmanager
import json
import logging
from typing import Any, List, Optional, Tuple, cast

from aries_askar import AskarError, AskarErrorCode, Key, KeyAlg, Store
import base58
from fastapi import Depends, FastAPI, Header, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import Base64UrlBytes, BaseModel, Field
from pydantic.types import Base64UrlEncoder


LOGGER = logging.getLogger("uvicorn.error." + __name__)
DEFAULT_PROFILE = "default"
PROFILE_HEADER = "X-Profile"


@asynccontextmanager
async def setup_store(app: FastAPI):
    """Setup the Askar store."""
    key = Store.generate_raw_key()
    store = await Store.provision(
        "sqlite://:memory:", "raw", key, profile=DEFAULT_PROFILE
    )
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


class ProblemDetails(BaseModel):
    """RFC 9457 Problem Details."""

    type: Optional[str] = None
    status: int
    title: str
    detail: Optional[str] = None

    def __str__(self) -> str:
        """Return short string representation of problem details object."""
        return f"{self.status}: {self.title}"

    @classmethod
    def NotFound(cls, detail: Optional[str] = None) -> "ProblemDetails":
        """Not Found problem details."""
        return cls(status=404, title="Not Found", detail=detail)

    @classmethod
    def InternalServerError(cls, detail: Optional[str] = None) -> "ProblemDetails":
        """Internal Error problem details."""
        return cls(
            status=500,
            title="Internal Server Error",
            detail=detail,
        )

    @classmethod
    def BadRequest(cls, detail: Optional[str] = None) -> "ProblemDetails":
        """Bad Request problem details."""
        return cls(
            status=400,
            title="Bad Request",
            detail=detail,
        )


class ProblemDetailsException(Exception):
    """Exception wrapper for problem details."""

    def __init__(self, details: ProblemDetails):
        """Initiliaze exception."""
        self.details = details

    @classmethod
    def NotFound(cls, detail: Optional[str] = None) -> "ProblemDetailsException":
        """Not Found problem details."""
        return cls(ProblemDetails(status=404, title="Not Found", detail=detail))

    @classmethod
    def InternalServerError(
        cls, detail: Optional[str] = None
    ) -> "ProblemDetailsException":
        """Internal Error problem details."""
        return cls(
            ProblemDetails(
                status=500,
                title="Internal Server Error",
                detail=detail,
            )
        )

    @classmethod
    def BadRequest(cls, detail: Optional[str] = None) -> "ProblemDetailsException":
        """Bad Request problem details."""
        return cls(
            ProblemDetails(
                status=400,
                title="Bad Request",
                detail=detail,
            )
        )


@app.exception_handler(ProblemDetailsException)
async def problem_details_exception_handler(_: Request, exc: ProblemDetailsException):
    """Handle ProblemDetails exceptions."""
    details = exc.details
    return JSONResponse(
        status_code=details.status,
        content=details.model_dump(exclude_none=True),
        headers={"Content-Type": "application/problem+json"},
    )


class ValidationErrorInfo(BaseModel):
    """Validation error info."""

    loc: Tuple[str, Any]
    msg: str
    type: str


class ValidationProblemDetails(ProblemDetails):
    """Problem details for validation errors."""

    errors: List[ValidationErrorInfo]


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors."""
    details = ValidationProblemDetails(
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        title="Validation Error",
        detail="Failed to validate request body",
        errors=[ValidationErrorInfo.model_validate(error) for error in exc.errors()],
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=details.model_dump(exclude_none=True),
    )


class ProfileReq(BaseModel):
    """Profile create request."""

    name: str


class ProfileResp(BaseModel):
    """Profile create response."""

    name: str


@app.post("/profile", tags=["profiles"], response_description="Profile create response")
async def create_profile(req: ProfileReq, store: Store = Depends(store)) -> ProfileResp:
    """Create a new Profile."""
    try:
        name = await store.create_profile(req.name)
    except AskarError as error:
        if error.code == AskarErrorCode.DUPLICATE:
            raise ProblemDetailsException.BadRequest(
                f"Profile with name '{req.name}' already exists"
            )
        else:
            raise ProblemDetailsException.InternalServerError(
                "Could not create profile"
            ) from error

    return ProfileResp(name=name)


class ProfileList(BaseModel):
    """List of Profiles."""

    profiles: List[str]


@app.get("/profiles", tags=["profiles"], response_description="Profile list")
async def get_profiles(store: Store = Depends(store)) -> ProfileList:
    """Get available profiles."""
    profiles = list(await store.list_profiles())
    return ProfileList(profiles=profiles)


@app.delete("/profile/{name}", tags=["profiles"], response_description="Success bool")
async def delete_profile(name: str, store: Store = Depends(store)):
    """Delete a profile."""
    ok = await store.remove_profile(name)
    return {"success": ok}


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


@app.post("/key/generate", tags=["keys"], response_description="The generated key")
async def generate_key(
    req: GenerateKeyReq,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> GenerateKeyResp:
    """Generate a key and store it."""
    key = Key.generate(req.alg)
    kid = derive_kid(key)
    async with store.session(profile=profile) as txn:
        await txn.insert_key(kid, key)
    return GenerateKeyResp.from_key(kid, key)


class AssociateKeyReq(BaseModel):
    """Associate Key Request body."""

    key_uri: str = Field(
        examples=["did:example:1234#key-1"],
        pattern=r"did:([a-z0-9]+):((?:[a-zA-Z0-9._%-]*:)*[a-zA-Z0-9._%-]+)#.*",
    )


class AssociateKeyResp(BaseModel):
    """Associate Key Response body."""

    key_uri: str
    kid: str


@app.post(
    "/key/{kid}/associate",
    tags=["keys"],
    response_description="Summary of associated identifiers",
)
async def associate_key(
    kid: str,
    req: AssociateKeyReq,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> AssociateKeyResp:
    """Associate a key with identifiers."""
    LOGGER.debug(
        "Associating key %s with: profile: %s, key_uri: %s",
        kid,
        profile,
        req.key_uri,
    )
    async with store.transaction(profile=profile) as txn:
        entry = await txn.fetch_key(kid, for_update=True)
        if not entry:
            raise ProblemDetailsException.NotFound("Key not found")

        did = req.key_uri.split("#", 1)[0]
        await txn.update_key(
            kid,
            tags={
                "key_uri": req.key_uri,
                "did": did,
            },
        )
        await txn.commit()

    return AssociateKeyResp(key_uri=req.key_uri, kid=kid)


@app.get("/key", tags=["keys"], response_description="Retrieved key")
async def get_key_by_identifier(
    key_uri: str,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> GenerateKeyResp:
    """Retrieve a key by identifier key_uri."""
    LOGGER.debug("Retrieving key with: profile: %s, key_uri: %s", profile, key_uri)
    async with store.session(profile=profile) as txn:
        entries = await txn.fetch_all_keys(tag_filter={"key_uri": key_uri}, limit=1)
        if not entries:
            raise ProblemDetailsException.NotFound("Key not found")

        kid = cast(str, entries[0].name)
        key = cast(Key, entries[0].key)
        return GenerateKeyResp.from_key(kid, key)


@app.get("/keys", tags=["keys"], response_description="List of keys")
async def get_all_keys(
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> List[GenerateKeyResp]:
    """Return list of all keys.

    WARNING: This will return at most 100 keys. Do not rely on this in production.
    """
    async with store.session(profile=profile) as txn:
        entries = await txn.fetch_all_keys(limit=100)

    return [
        GenerateKeyResp.from_key(cast(str, entry.name), cast(Key, entry.key))
        for entry in entries
    ]


@app.get("/key/{kid}", tags=["keys"], response_description="Retrieved key")
async def get_key(
    kid: str,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> GenerateKeyResp:
    """Get a key by its kid."""
    async with store.session(profile=profile) as txn:
        key_entry = await txn.fetch_key(kid)

    if key_entry:
        key = cast(Key, key_entry.key)
    else:
        raise ProblemDetailsException.NotFound("Key not found")

    return GenerateKeyResp.from_key(kid, key)


@app.delete("/key/{kid}", tags=["keys"], response_description="Deleted kid")
async def delete_key(
    kid: str,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
):
    """Delete a key by its kid."""
    async with store.session(profile=profile) as txn:
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
    "/sign", tags=["ops"], response_description="Signed message in base64url encoding"
)
async def sign(
    req: SigReq,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> SigResp:
    """Sign a message with a key."""
    async with store.session(profile=profile) as txn:
        key_entry = await txn.fetch_key(req.kid)
    if key_entry:
        key = cast(Key, key_entry.key)
    else:
        raise ProblemDetailsException.NotFound("Key not found")

    sig = key.sign_message(req.data)
    return SigResp(sig=Base64UrlEncoder.encode(sig))
