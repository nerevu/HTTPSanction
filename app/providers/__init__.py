# To use this code, make sure you
#
#     import json
#
# and then, to convert JSON from a string, do
#
#     result = provider_from_dict(json.loads(json_string))

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union, cast

T = TypeVar("T")


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return {k: f(v) for (k, v) in x.items()}


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


@dataclass
class Headers:
    """HTTP headers to include with requests (case sensitive)"""

    """Include in all requests"""
    all: Optional[Dict[str, Union[bool, int, str]]]
    """Include only in DELETE requests"""
    delete: Optional[Dict[str, Union[bool, int, str]]]
    """Include only in GET requests"""
    get: Optional[Dict[str, Union[bool, int, str]]]
    """Include only in PATCH requests"""
    patch: Optional[Dict[str, Union[bool, int, str]]]
    """Include only in POST requests"""
    post: Optional[Dict[str, Union[bool, int, str]]]
    """Include only in PUT requests"""
    put: Optional[Dict[str, Union[bool, int, str]]]

    @staticmethod
    def from_dict(obj: Any) -> "Headers":
        assert isinstance(obj, dict)
        all = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            obj.get("ALL"),
        )
        delete = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            obj.get("DELETE"),
        )
        get = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            obj.get("GET"),
        )
        patch = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            obj.get("PATCH"),
        )
        post = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            obj.get("POST"),
        )
        put = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            obj.get("PUT"),
        )
        return Headers(all, delete, get, patch, post, put)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ALL"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            self.all,
        )
        result["DELETE"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            self.delete,
        )
        result["GET"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            self.get,
        )
        result["PATCH"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            self.patch,
        )
        result["POST"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            self.post,
        )
        result["PUT"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            self.put,
        )
        return result


@dataclass
class HeadlessElement:
    """An element on a provider's application login page"""

    """User friendly identification of the element"""
    description: str
    """CSS selector of the element"""
    selector: str
    """Action to perform on the element"""
    action: Optional[str]
    """Text to send to the element (can't be mixed with `prompt`)"""
    content: Optional[str]
    """Text to display when requesting user input (can't be mixed with `content`)."""
    prompt: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "HeadlessElement":
        assert isinstance(obj, dict)
        description = from_str(obj.get("description"))
        selector = from_str(obj.get("selector"))
        action = from_union([from_none, from_str], obj.get("action"))
        content = from_union([from_none, from_str], obj.get("content"))
        prompt = from_union([from_none, from_str], obj.get("prompt"))
        return HeadlessElement(description, selector, action, content, prompt)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_str(self.description)
        result["selector"] = from_str(self.selector)
        result["action"] = from_union([from_none, from_str], self.action)
        result["content"] = from_union([from_none, from_str], self.content)
        result["prompt"] = from_union([from_none, from_str], self.prompt)
        return result


@dataclass
class Authentication:
    """API authentication"""

    """Base API URL"""
    api_base_url: Optional[str]
    attrs: Optional[Dict[str, Union[bool, int, str]]]
    """Unique identifier for the API resource"""
    auth_id: Optional[str]
    """Unique API authentication type"""
    auth_type: Optional[str]
    """API OAuth authorization URL"""
    authorization_base_url: Optional[str]
    """The API client ID"""
    client_id: Optional[str]
    """The API client secret"""
    client_secret: Optional[str]
    """Enable debug mode"""
    debug: Optional[bool]
    """URL to API reference documentation"""
    documentation_url: Optional[str]
    """OAuth2 flow enum"""
    flow_enum: Optional[int]
    """OAuth2 flow type"""
    flow_type: Optional[str]
    """HTTP headers to include with requests (case sensitive)"""
    headers: Optional[Headers]
    """Allow headless authentication"""
    headless: Optional[bool]
    """Web element used to navigate a provider's application login page"""
    headless_elements: Optional[List[HeadlessElement]]
    """Use this authentication object if one isn't provided"""
    is_default: Optional[bool]
    params: Optional[Dict[str, Union[bool, int, str]]]
    """The base authentication object"""
    parent: Optional[str]
    """The application password"""
    password: Optional[str]
    """API OAuth flow callback entry point (defaults to `$PROVIDER_PREFIX-callback`"""
    redirect_uri: Optional[str]
    """API OAuth token refresh URL (defaults to the `tokenURL`)"""
    refresh_url: Optional[str]
    """OAuth2 flow requires basic authentication"""
    requires_basic_auth: Optional[bool]
    """The API permissions scope"""
    scope: Optional[List[str]]
    """API OAuth token URL"""
    token_url: Optional[str]
    """The application username"""
    username: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "Authentication":
        assert isinstance(obj, dict)
        api_base_url = from_union([from_none, from_str], obj.get("apiBaseURL"))
        attrs = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            obj.get("attrs"),
        )
        auth_id = from_union([from_none, from_str], obj.get("authId"))
        auth_type = from_union([from_none, from_str], obj.get("authType"))
        authorization_base_url = from_union(
            [from_none, from_str], obj.get("authorizationBaseURL")
        )
        client_id = from_union([from_none, from_str], obj.get("clientId"))
        client_secret = from_union([from_none, from_str], obj.get("clientSecret"))
        debug = from_union([from_bool, from_none], obj.get("debug"))
        documentation_url = from_union(
            [from_none, from_str], obj.get("documentationURL")
        )
        flow_enum = from_union([from_int, from_none], obj.get("flowEnum"))
        flow_type = from_union([from_none, from_str], obj.get("flowType"))
        headers = from_union([Headers.from_dict, from_none], obj.get("headers"))
        headless = from_union([from_bool, from_none], obj.get("headless"))
        headless_elements = from_union(
            [lambda x: from_list(HeadlessElement.from_dict, x), from_none],
            obj.get("headlessElements"),
        )
        is_default = from_union([from_bool, from_none], obj.get("isDefault"))
        params = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            obj.get("params"),
        )
        parent = from_union([from_none, from_str], obj.get("parent"))
        password = from_union([from_none, from_str], obj.get("password"))
        redirect_uri = from_union([from_none, from_str], obj.get("redirectURI"))
        refresh_url = from_union([from_none, from_str], obj.get("refreshURL"))
        requires_basic_auth = from_union(
            [from_bool, from_none], obj.get("requiresBasicAuth")
        )
        scope = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("scope")
        )
        token_url = from_union([from_none, from_str], obj.get("tokenURL"))
        username = from_union([from_none, from_str], obj.get("username"))
        return Authentication(
            api_base_url,
            attrs,
            auth_id,
            auth_type,
            authorization_base_url,
            client_id,
            client_secret,
            debug,
            documentation_url,
            flow_enum,
            flow_type,
            headers,
            headless,
            headless_elements,
            is_default,
            params,
            parent,
            password,
            redirect_uri,
            refresh_url,
            requires_basic_auth,
            scope,
            token_url,
            username,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["apiBaseURL"] = from_union([from_none, from_str], self.api_base_url)
        result["attrs"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            self.attrs,
        )
        result["authId"] = from_union([from_none, from_str], self.auth_id)
        result["authType"] = from_union([from_none, from_str], self.auth_type)
        result["authorizationBaseURL"] = from_union(
            [from_none, from_str], self.authorization_base_url
        )
        result["clientId"] = from_union([from_none, from_str], self.client_id)
        result["clientSecret"] = from_union([from_none, from_str], self.client_secret)
        result["debug"] = from_union([from_bool, from_none], self.debug)
        result["documentationURL"] = from_union(
            [from_none, from_str], self.documentation_url
        )
        result["flowEnum"] = from_union([from_int, from_none], self.flow_enum)
        result["flowType"] = from_union([from_none, from_str], self.flow_type)
        result["headers"] = from_union(
            [lambda x: to_class(Headers, x), from_none], self.headers
        )
        result["headless"] = from_union([from_bool, from_none], self.headless)
        result["headlessElements"] = from_union(
            [lambda x: from_list(lambda x: to_class(HeadlessElement, x), x), from_none],
            self.headless_elements,
        )
        result["isDefault"] = from_union([from_bool, from_none], self.is_default)
        result["params"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union([from_bool, from_int, from_str], x), x
                ),
                from_none,
            ],
            self.params,
        )
        result["parent"] = from_union([from_none, from_str], self.parent)
        result["password"] = from_union([from_none, from_str], self.password)
        result["redirectURI"] = from_union([from_none, from_str], self.redirect_uri)
        result["refreshURL"] = from_union([from_none, from_str], self.refresh_url)
        result["requiresBasicAuth"] = from_union(
            [from_bool, from_none], self.requires_basic_auth
        )
        result["scope"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.scope
        )
        result["tokenURL"] = from_union([from_none, from_str], self.token_url)
        result["username"] = from_union([from_none, from_str], self.username)
        return result


@dataclass
class Provider:
    """A 3rd party API provider"""

    """Authentication methods accepted by API provider"""
    auths: List[Authentication]
    """Unique API provider identifier"""
    prefix: str

    @staticmethod
    def from_dict(obj: Any) -> "Provider":
        assert isinstance(obj, dict)
        auths = from_list(Authentication.from_dict, obj.get("auths"))
        prefix = from_str(obj.get("prefix"))
        return Provider(auths, prefix)

    def to_dict(self) -> dict:
        result: dict = {}
        result["auths"] = from_list(lambda x: to_class(Authentication, x), self.auths)
        result["prefix"] = from_str(self.prefix)
        return result


def provider_from_dict(s: Any) -> Provider:
    return Provider.from_dict(s)


def provider_to_dict(x: Provider) -> Any:
    return to_class(Provider, x)
