"""A Mini KMS server using Askar for key management."""

from contextlib import asynccontextmanager
import json
import logging
from typing import Any, List, Mapping, Optional, Sequence, Set, Tuple, cast
from uuid import uuid4

from aries_askar import AskarError, AskarErrorCode, Entry, Key, KeyAlg, Store
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
    version="0.1.1",
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

    alias: str = Field(
        examples=["did:example:1234#key-1"],
    )


class AssociateKeyResp(BaseModel):
    """Associate Key Response body."""

    alias: str
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
        "Associating key %s with: profile: %s, alias: %s",
        kid,
        profile,
        req.alias,
    )
    async with store.transaction(profile=profile) as txn:
        entry = await txn.fetch_key(kid, for_update=True)
        if not entry:
            raise ProblemDetailsException.NotFound("Key not found")

        did = req.alias.split("#", 1)[0]
        await txn.update_key(
            kid,
            tags={
                "alias": req.alias,
                "did": did,
            },
        )
        await txn.commit()

    return AssociateKeyResp(alias=req.alias, kid=kid)


@app.get("/key", tags=["keys"], response_description="Retrieved key")
async def get_key_by_alias(
    alias: str,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> GenerateKeyResp:
    """Retrieve a key by identifier alias."""
    LOGGER.debug("Retrieving key with: profile: %s, alias: %s", profile, alias)
    async with store.session(profile=profile) as txn:
        entries = await txn.fetch_all_keys(tag_filter={"alias": alias}, limit=1)
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


class VCRecord(BaseModel):
    """Credential storage request."""

    contexts: Set[str]
    expanded_types: Set[str]
    issuer_id: str
    subject_ids: Set[str]
    schema_ids: Set[str]
    proof_types: Set[str]
    cred_value: Mapping
    given_id: Optional[str] = None
    cred_tags: Optional[Mapping] = None
    record_id: Optional[str] = None


class CredStoreResult(BaseModel):
    """Result of credential storage."""

    record_id: str


VC_HOLDER_CAT = "vc-holder"


@app.post(
    "/vc-holder/store", tags=["vc-holder"], response_description="Stored credential id"
)
async def store_credential(
    cred: VCRecord,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
):
    """Store a credential."""
    tags = {
        attr: value
        for attr in (
            "contexts",
            "expanded_types",
            "schema_ids",
            "subject_ids",
            "proof_types",
            "issuer_id",
            "given_id",
        )
        if (value := getattr(cred, attr))
    }
    for tagname, tagval in (cred.cred_tags or {}).items():
        tags[f"cstm:{tagname}"] = tagval

    record_id = cred.record_id or str(uuid4())
    async with store.session(profile=profile) as txn:
        await txn.insert(
            category=VC_HOLDER_CAT, name=record_id, tags=tags, value_json=cred.cred_value
        )
    return CredStoreResult(record_id=record_id)


def entry_to_vc_record(entry: Entry) -> VCRecord:
    """Convert an Askar stored entry into a VC record."""
    tags = cast(dict, entry.tags)
    cred_tags = {name[5:]: value for name, value in tags if name.startswith("cstm:")}
    contexts = tags.get("contexts", set())
    types = tags.get("expanded_types", set())
    schema_ids = tags.get("schema_ids", set())
    subject_ids = tags.get("subject_ids", set())
    proof_types = tags.get("proof_types", set())
    issuer_id = tags.get("issuer_id")
    if not isinstance(issuer_id, str):
        raise ValueError("issuer_id must be str")
    given_id = tags.get("given_id")
    return VCRecord(
        contexts=contexts,
        expanded_types=types,
        schema_ids=schema_ids,
        issuer_id=issuer_id,
        subject_ids=subject_ids,
        proof_types=proof_types,
        cred_value=json.loads(entry.value),
        given_id=given_id,
        cred_tags=cred_tags,
        record_id=cast(str, entry.name),
    )


@app.get(
    "/vc-holder/credential/record/{record_id}",
    tags=["vc-holder"],
    response_description="Retrieved credential",
)
async def retrieve_credential_by_id(
    record_id: str,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> VCRecord:
    """Retrieve a credential by id."""
    async with store.session(profile=profile) as txn:
        entry = await txn.fetch(VC_HOLDER_CAT, record_id)
        if not entry:
            raise ProblemDetailsException.NotFound(
                f"No credential record found for id {record_id}"
            )

        return entry_to_vc_record(entry)


@app.get(
    "/vc-holder/credential/given/{record_id}",
    tags=["vc-holder"],
    response_description="Retrieved credential",
)
async def retrieve_credential_by_given_id(
    given_id: str,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> VCRecord:
    """Retrieve a credential by id."""
    async with store.session(profile=profile) as txn:
        entries = await txn.fetch_all(VC_HOLDER_CAT, {"given_id": given_id}, limit=2)
        if not entries:
            raise ProblemDetailsException.NotFound(
                f"No credential record found for given id {given_id}"
            )

        if len(entries) > 1:
            raise ProblemDetailsException.BadRequest(
                f"Duplicate record found for given id {given_id}"
            )

        return entry_to_vc_record(entries[0])


@app.delete(
    "/vc-holder/credential/record/{record_id}",
    tags=["vc-holder"],
    response_description="Retrieved credential",
)
async def delete_credential(
    record_id: str,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> None:
    """Delete a credential."""
    async with store.session(profile=profile) as txn:
        # TODO error handling
        await txn.remove(VC_HOLDER_CAT, record_id)


class VCRecords(BaseModel):
    """Records from a search."""

    records: List[VCRecord]


def build_type_or_schema_query(uri_list: Sequence[str]) -> dict:
    """Build and return indy-specific type_or_schema_query."""
    type_or_schema_query: dict[str, Any] = {}
    for uri in uri_list:
        q = {"$or": [{"type": uri}, {"schema": uri}]}
        if type_or_schema_query:
            if "$and" not in type_or_schema_query:
                type_or_schema_query = {"$and": [type_or_schema_query]}
            type_or_schema_query["$and"].append(q)
        else:
            type_or_schema_query = q
    return type_or_schema_query


class CredSearchReq(BaseModel):
    """Credential search request body."""

    contexts: Optional[List[str]] = None
    types: Optional[List[str]] = None
    schema_ids: Optional[List[str]] = None
    issuer_id: Optional[str] = None
    subject_ids: Optional[str] = None
    proof_types: Optional[List[str]] = None
    given_id: Optional[str] = None
    tag_query: Optional[Mapping] = None
    pd_uri_list: Optional[List[str]] = None
    offset: int = 0
    limit: int = 10


@app.post(
    "/vc-holder/credentials",
    tags=["vc-holder"],
    response_description="Retrieved credentials",
)
async def search_credentials(  # noqa: C901
    req: CredSearchReq,
    profile: str = Header(default=DEFAULT_PROFILE, alias=PROFILE_HEADER),
    store: Store = Depends(store),
) -> VCRecords:
    """Search for credentials."""
    offset = req.offset or 0
    offset = 0 if offset < 0 else offset
    limit = req.limit or 10
    limit = 50 if limit > 50 else limit

    def _match_any(query: list, k, vals):
        if vals is None:
            pass
        elif len(vals) > 1:
            query.append({"$or": [{k: v for v in vals}]})
        else:
            query.append({k: vals[0]})

    def _make_custom_query(query):
        result = {}
        for k, v in query.items():
            if isinstance(v, (list, set)) and k != "$exist":
                result[k] = [_make_custom_query(cl) for cl in v]
            elif k.startswith("$"):
                result[k] = v
            else:
                result[f"cstm:{k}"] = v
        return result

    query = []
    _match_any(query, "contexts", req.contexts)
    _match_any(query, "expanded_types", req.types)
    _match_any(query, "schema_ids", req.schema_ids)
    _match_any(query, "subject_ids", req.subject_ids)
    _match_any(query, "proof_types", req.proof_types)
    if req.issuer_id:
        query.append({"issuer_id": req.issuer_id})
    if req.given_id:
        query.append({"given_id": req.given_id})
    if req.tag_query:
        query.append(_make_custom_query(req.tag_query))
    if req.pd_uri_list:
        query.append(build_type_or_schema_query(req.pd_uri_list))

    query = {"$and": query} if query else {}
    scan = store.scan(VC_HOLDER_CAT, query, offset=offset, limit=limit, profile=profile)
    entries = await scan.fetch_all()
    return VCRecords(records=[entry_to_vc_record(entry) for entry in entries])
