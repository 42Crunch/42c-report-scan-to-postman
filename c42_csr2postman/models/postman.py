from typing import List, Union
from dataclasses import dataclass, field

from .interfaces import *

# -------------------------------------------------------------------------
# Shared
# -------------------------------------------------------------------------
@dataclass
class PostmanProperty(Serializable):
    key: str
    value: str

# -------------------------------------------------------------------------
# Collection variables
# -------------------------------------------------------------------------
@dataclass
class PostmanVariables(Serializable):
    variables: List[PostmanProperty] = field(default_factory=list)

# -------------------------------------------------------------------------
# Generic information for a Postman Class
# -------------------------------------------------------------------------
@dataclass
class PostmanInfo(Serializable):
    name: str
    description: str
    schema: str = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"


# -------------------------------------------------------------------------
# End-Points definitions
# -------------------------------------------------------------------------
@dataclass
class PostmanAuthAPIKey(Serializable):
    key: str
    value: str
    type: str = "string"

@dataclass
class PostmanAuth(Serializable):
    type: str
    apikey: List[PostmanAuthAPIKey]

@dataclass
class PostmanUrl(Serializable):
    raw: str
    host: List[str] = field(default_factory=list)
    path: List[str] = field(default_factory=list)

@dataclass
class PostmanRequest(Serializable):
    method: str
    url: PostmanUrl
    description: str = ""
    header: List[PostmanProperty] = field(default_factory=list)
    auth: PostmanAuth = None

@dataclass
class PostmanResponse(Serializable):
    name: str
    originalRequest = PostmanRequest
    status: str
    code: int
    body: str = ""
    _postman_previewlanguage: str = "json"
    header: List[PostmanProperty] = field(default_factory=list)
    cookie: List[PostmanProperty] = field(default_factory=list)

@dataclass
class PostmanEndPoint(Serializable):
    name: str
    request: PostmanRequest
    response: List[PostmanResponse] = None

@dataclass
class PostmanPackage(Serializable):
    name: str
    items: List[PostmanEndPoint] = field(default_factory=list)

# -------------------------------------------------------------------------
# Postman collection group
# -------------------------------------------------------------------------
@dataclass
class PostmanConfigFile(Serializable):
    info: PostmanInfo
    variables: PostmanVariables = field(default_factory=PostmanVariables)
    items: PostmanPackage or List[PostmanEndPoint] = field(default_factory=list)
