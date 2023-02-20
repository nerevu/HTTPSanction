# This code parses date/times, so please
#
#     pip install python-dateutil
#
# To use this code, make sure you
#
#     import json
#
# and then, to convert JSON from a string, do
#
#     result = provider_from_dict(json.loads(json_string))

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union, cast

import dateutil.parser

T = TypeVar("T")


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return {k: f(v) for (k, v) in x.items()}


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def from_float(x: Any) -> float:
    assert isinstance(x, (float, int)) and not isinstance(x, bool)
    return float(x)


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


def to_float(x: Any) -> float:
    assert isinstance(x, float)
    return x


@dataclass
class Conditional:
    """description"""

    """description"""
    result: Optional[List[str]]
    """description"""
    test: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "Conditional":
        assert isinstance(obj, dict)
        result = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("result")
        )
        test = from_union([from_none, from_str], obj.get("test"))
        return Conditional(result, test)

    def to_dict(self) -> dict:
        result: dict = {}
        result["result"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.result
        )
        result["test"] = from_union([from_none, from_str], self.test)
        return result


@dataclass
class AttrClass:
    """description"""

    conditional: Optional[Conditional]
    """Function to apply to the Status resource json response"""
    func: Optional[str]
    """Path to the attribute relative to the Status resource json response"""
    path: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "AttrClass":
        assert isinstance(obj, dict)
        conditional = from_union(
            [Conditional.from_dict, from_none], obj.get("conditional")
        )
        func = from_union([from_none, from_str], obj.get("func"))
        path = from_union([from_none, from_str], obj.get("path"))
        return AttrClass(conditional, func, path)

    def to_dict(self) -> dict:
        result: dict = {}
        result["conditional"] = from_union(
            [lambda x: to_class(Conditional, x), from_none], self.conditional
        )
        result["func"] = from_union([from_none, from_str], self.func)
        result["path"] = from_union([from_none, from_str], self.path)
        return result


@dataclass
class AuthenticationHeaders:
    """HTTP headers to include with requests (case sensitive)"""

    """Include in all requests"""
    all: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in DELETE requests"""
    delete: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in GET requests"""
    get: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in PATCH requests"""
    patch: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in POST requests"""
    post: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in PUT requests"""
    put: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]

    @staticmethod
    def from_dict(obj: Any) -> "AuthenticationHeaders":
        assert isinstance(obj, dict)
        all = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("ALL"),
        )
        delete = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("DELETE"),
        )
        get = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("GET"),
        )
        patch = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("PATCH"),
        )
        post = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("POST"),
        )
        put = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("PUT"),
        )
        return AuthenticationHeaders(all, delete, get, patch, post, put)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ALL"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.all,
        )
        result["DELETE"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.delete,
        )
        result["GET"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.get,
        )
        result["PATCH"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.patch,
        )
        result["POST"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.post,
        )
        result["PUT"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
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
class MethodMap:
    """Maps standard HTTP methods to API specific methods (case sensitive)"""

    """Map DELETE requests"""
    delete: Optional[str]
    """Map GET requests"""
    get: Optional[str]
    """Map PATCH requests"""
    patch: Optional[str]
    """Map POST requests"""
    post: Optional[str]
    """Map PUT requests"""
    put: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "MethodMap":
        assert isinstance(obj, dict)
        delete = from_union([from_none, from_str], obj.get("DELETE"))
        get = from_union([from_none, from_str], obj.get("GET"))
        patch = from_union([from_none, from_str], obj.get("PATCH"))
        post = from_union([from_none, from_str], obj.get("POST"))
        put = from_union([from_none, from_str], obj.get("PUT"))
        return MethodMap(delete, get, patch, post, put)

    def to_dict(self) -> dict:
        result: dict = {}
        result["DELETE"] = from_union([from_none, from_str], self.delete)
        result["GET"] = from_union([from_none, from_str], self.get)
        result["PATCH"] = from_union([from_none, from_str], self.patch)
        result["POST"] = from_union([from_none, from_str], self.post)
        result["PUT"] = from_union([from_none, from_str], self.put)
        return result


@dataclass
class ParamMap:
    """Maps standard parameters to API specific parameters"""

    """The end date"""
    end: Optional[str]
    fields: Optional[str]
    id: Optional[str]
    """The start date"""
    start: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "ParamMap":
        assert isinstance(obj, dict)
        end = from_union([from_none, from_str], obj.get("end"))
        fields = from_union([from_none, from_str], obj.get("fields"))
        id = from_union([from_none, from_str], obj.get("id"))
        start = from_union([from_none, from_str], obj.get("start"))
        return ParamMap(end, fields, id, start)

    def to_dict(self) -> dict:
        result: dict = {}
        result["end"] = from_union([from_none, from_str], self.end)
        result["fields"] = from_union([from_none, from_str], self.fields)
        result["id"] = from_union([from_none, from_str], self.id)
        result["start"] = from_union([from_none, from_str], self.start)
        return result


@dataclass
class Authentication:
    """API authentication"""

    """Base API URL"""
    api_base_url: Optional[str]
    """Extension to place  at the end of API urls"""
    api_ext: Optional[str]
    attrs: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Unique identifier for the API resource"""
    auth_id: Optional[str]
    """The API authentication type"""
    auth_type: Optional[str]
    """API OAuth authorization URL"""
    authorization_base_url: Optional[str]
    """The API client ID"""
    client_id: Optional[str]
    """The API client secret"""
    client_secret: Optional[str]
    """Key to assign data to for POST/PATCH requests"""
    data_key: Optional[str]
    """Enable debug mode"""
    debug: Optional[bool]
    """URL to API reference documentation"""
    documentation_url: Optional[str]
    """An example API request"""
    example: Optional[str]
    """Key/Value pairs where key -> Attribute to store the extracted path in, and value -> Path
    to extract from the json authentication result
    """
    extractions: Optional[Dict[str, str]]
    """OAuth2 flow enum"""
    flow_enum: Optional[int]
    """OAuth2 flow type: web -> Authorization Grant Type, mobile -> Implicit Code Grant Type,
    legacy -> Password Credentials Grant Type, backend -> Client Credentials Grant Type
    """
    flow_type: Optional[str]
    """HTTP headers to include with requests (case sensitive)"""
    headers: Optional[AuthenticationHeaders]
    """Allow headless authentication"""
    headless: Optional[bool]
    """Web element used to navigate a provider's application login page"""
    headless_elements: Optional[List[HeadlessElement]]
    """Use this authentication object if one isn't provided"""
    is_default: Optional[bool]
    """Maps standard HTTP methods to API specific methods (case sensitive)"""
    method_map: Optional[MethodMap]
    """Maps standard parameters to API specific parameters"""
    param_map: Optional[ParamMap]
    params: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
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
    """API OAuth token revocation URL"""
    revoke_url: Optional[str]
    """Place the resource ID *after* the subresource instead of before"""
    rid_last: Optional[bool]
    """The API permissions scope"""
    scope: Optional[List[str]]
    """Wrap data in a singularized resource name for POST/PATCH requests"""
    singularize: Optional[bool]
    """The path to extract from the parsed API response (should return a list of items)"""
    subkey: Optional[str]
    """API OAuth token URL"""
    token_url: Optional[str]
    """The application username"""
    username: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "Authentication":
        assert isinstance(obj, dict)
        api_base_url = from_union([from_none, from_str], obj.get("apiBaseURL"))
        api_ext = from_union([from_none, from_str], obj.get("apiExt"))
        attrs = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
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
        data_key = from_union([from_none, from_str], obj.get("dataKey"))
        debug = from_union([from_bool, from_none], obj.get("debug"))
        documentation_url = from_union(
            [from_none, from_str], obj.get("documentationURL")
        )
        example = from_union([from_none, from_str], obj.get("example"))
        extractions = from_union(
            [lambda x: from_dict(from_str, x), from_none], obj.get("extractions")
        )
        flow_enum = from_union([from_int, from_none], obj.get("flowEnum"))
        flow_type = from_union([from_none, from_str], obj.get("flowType"))
        headers = from_union(
            [AuthenticationHeaders.from_dict, from_none], obj.get("headers")
        )
        headless = from_union([from_bool, from_none], obj.get("headless"))
        headless_elements = from_union(
            [lambda x: from_list(HeadlessElement.from_dict, x), from_none],
            obj.get("headlessElements"),
        )
        is_default = from_union([from_bool, from_none], obj.get("isDefault"))
        method_map = from_union([MethodMap.from_dict, from_none], obj.get("methodMap"))
        param_map = from_union([ParamMap.from_dict, from_none], obj.get("paramMap"))
        params = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
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
        revoke_url = from_union([from_none, from_str], obj.get("revokeUrl"))
        rid_last = from_union([from_bool, from_none], obj.get("ridLast"))
        scope = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("scope")
        )
        singularize = from_union([from_bool, from_none], obj.get("singularize"))
        subkey = from_union([from_none, from_str], obj.get("subkey"))
        token_url = from_union([from_none, from_str], obj.get("tokenURL"))
        username = from_union([from_none, from_str], obj.get("username"))
        return Authentication(
            api_base_url,
            api_ext,
            attrs,
            auth_id,
            auth_type,
            authorization_base_url,
            client_id,
            client_secret,
            data_key,
            debug,
            documentation_url,
            example,
            extractions,
            flow_enum,
            flow_type,
            headers,
            headless,
            headless_elements,
            is_default,
            method_map,
            param_map,
            params,
            parent,
            password,
            redirect_uri,
            refresh_url,
            requires_basic_auth,
            revoke_url,
            rid_last,
            scope,
            singularize,
            subkey,
            token_url,
            username,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["apiBaseURL"] = from_union([from_none, from_str], self.api_base_url)
        result["apiExt"] = from_union([from_none, from_str], self.api_ext)
        result["attrs"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
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
        result["dataKey"] = from_union([from_none, from_str], self.data_key)
        result["debug"] = from_union([from_bool, from_none], self.debug)
        result["documentationURL"] = from_union(
            [from_none, from_str], self.documentation_url
        )
        result["example"] = from_union([from_none, from_str], self.example)
        result["extractions"] = from_union(
            [lambda x: from_dict(from_str, x), from_none], self.extractions
        )
        result["flowEnum"] = from_union([from_int, from_none], self.flow_enum)
        result["flowType"] = from_union([from_none, from_str], self.flow_type)
        result["headers"] = from_union(
            [lambda x: to_class(AuthenticationHeaders, x), from_none], self.headers
        )
        result["headless"] = from_union([from_bool, from_none], self.headless)
        result["headlessElements"] = from_union(
            [lambda x: from_list(lambda x: to_class(HeadlessElement, x), x), from_none],
            self.headless_elements,
        )
        result["isDefault"] = from_union([from_bool, from_none], self.is_default)
        result["methodMap"] = from_union(
            [lambda x: to_class(MethodMap, x), from_none], self.method_map
        )
        result["paramMap"] = from_union(
            [lambda x: to_class(ParamMap, x), from_none], self.param_map
        )
        result["params"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
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
        result["revokeUrl"] = from_union([from_none, from_str], self.revoke_url)
        result["ridLast"] = from_union([from_bool, from_none], self.rid_last)
        result["scope"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.scope
        )
        result["singularize"] = from_union([from_bool, from_none], self.singularize)
        result["subkey"] = from_union([from_none, from_str], self.subkey)
        result["tokenURL"] = from_union([from_none, from_str], self.token_url)
        result["username"] = from_union([from_none, from_str], self.username)
        return result


@dataclass
class Filter:
    """description"""

    """description"""
    comparator: str
    """description"""
    field: str
    """description"""
    value: str

    @staticmethod
    def from_dict(obj: Any) -> "Filter":
        assert isinstance(obj, dict)
        comparator = from_str(obj.get("comparator"))
        field = from_str(obj.get("field"))
        value = from_str(obj.get("value"))
        return Filter(comparator, field, value)

    def to_dict(self) -> dict:
        result: dict = {}
        result["comparator"] = from_str(self.comparator)
        result["field"] = from_str(self.field)
        result["value"] = from_str(self.value)
        return result


@dataclass
class ResourceHeaders:
    """HTTP headers to include with requests (case sensitive)"""

    """Include in all requests"""
    all: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in DELETE requests"""
    delete: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in GET requests"""
    get: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in PATCH requests"""
    patch: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in POST requests"""
    post: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """Include only in PUT requests"""
    put: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]

    @staticmethod
    def from_dict(obj: Any) -> "ResourceHeaders":
        assert isinstance(obj, dict)
        all = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("ALL"),
        )
        delete = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("DELETE"),
        )
        get = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("GET"),
        )
        patch = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("PATCH"),
        )
        post = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("POST"),
        )
        put = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("PUT"),
        )
        return ResourceHeaders(all, delete, get, patch, post, put)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ALL"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.all,
        )
        result["DELETE"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.delete,
        )
        result["GET"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.get,
        )
        result["PATCH"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.patch,
        )
        result["POST"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.post,
        )
        result["PUT"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.put,
        )
        return result


@dataclass
class Resource:
    """An API resource"""

    """Unique identifier for the API resource"""
    resource_id: str
    attrs: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """The authorization object used to authenticate"""
    auth_id: Optional[str]
    """The the number of days to fetch data for"""
    days: Optional[float]
    """Convert response to a dictionary"""
    dictify: Optional[bool]
    """URL to API resource documentation"""
    documentation_url: Optional[str]
    """`json.dumps` data for POST/PATCH requests"""
    dump_data: Optional[bool]
    """The last date to fetch data for (defaults to today)"""
    end: Optional[datetime]
    """Is resource at the end of the stream?"""
    eof: Optional[bool]
    """An example API request"""
    example: Optional[str]
    """Resource fields to save from the parsed API response"""
    fields: Optional[List[str]]
    """description"""
    filter: Optional[Filter]
    """HTTP headers to include with requests (case sensitive)"""
    headers: Optional[ResourceHeaders]
    """Hide the resource from"""
    hidden: Optional[bool]
    """Field representing the resource ID (defaults to first field that equals `id` or ends with
    either `_id` or `Id`)
    """
    id_field: Optional[str]
    """HTTP methods this resource allows"""
    methods: Optional[List[str]]
    """Field representing the resource name (defaults to first field that equals or ends with
    `name`)
    """
    name_field: Optional[str]
    """Space to document API inconsistencies"""
    note: Optional[str]
    params: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """resourceId of the base resource object"""
    parent: Optional[str]
    """Starting position item to fetch"""
    pos: Optional[float]
    """What the resource is named in the API URL (defaults to `resourceId`)"""
    resource_name: Optional[str]
    """The path to extract from the parsed API response (should return a list of items)"""
    result_key: Optional[str]
    """Currently active resource"""
    rid: Optional[str]
    """Currently active sub resource"""
    srid: Optional[str]
    """The first date to fetch data from"""
    start: Optional[datetime]
    """The path to extract from the parsed API response (should return a list of items)"""
    subkey: Optional[str]
    """What the sub resource is named in the API URL"""
    subresource: Optional[str]
    """The url of a resource endpoint"""
    url: Optional[str]
    """Use default"""
    use_default: Optional[bool]

    @staticmethod
    def from_dict(obj: Any) -> "Resource":
        assert isinstance(obj, dict)
        resource_id = from_str(obj.get("resourceId"))
        attrs = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("attrs"),
        )
        auth_id = from_union([from_none, from_str], obj.get("authId"))
        days = from_union([from_float, from_none], obj.get("days"))
        dictify = from_union([from_bool, from_none], obj.get("dictify"))
        documentation_url = from_union(
            [from_none, from_str], obj.get("documentationURL")
        )
        dump_data = from_union([from_bool, from_none], obj.get("dumpData"))
        end = from_union([from_datetime, from_none], obj.get("end"))
        eof = from_union([from_bool, from_none], obj.get("eof"))
        example = from_union([from_none, from_str], obj.get("example"))
        fields = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("fields")
        )
        filter = from_union([Filter.from_dict, from_none], obj.get("filter"))
        headers = from_union([ResourceHeaders.from_dict, from_none], obj.get("headers"))
        hidden = from_union([from_bool, from_none], obj.get("hidden"))
        id_field = from_union([from_none, from_str], obj.get("idField"))
        methods = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("methods")
        )
        name_field = from_union([from_none, from_str], obj.get("nameField"))
        note = from_union([from_none, from_str], obj.get("note"))
        params = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("params"),
        )
        parent = from_union([from_none, from_str], obj.get("parent"))
        pos = from_union([from_float, from_none], obj.get("pos"))
        resource_name = from_union([from_none, from_str], obj.get("resourceName"))
        result_key = from_union([from_none, from_str], obj.get("resultKey"))
        rid = from_union([from_none, from_str], obj.get("rid"))
        srid = from_union([from_none, from_str], obj.get("srid"))
        start = from_union([from_datetime, from_none], obj.get("start"))
        subkey = from_union([from_none, from_str], obj.get("subkey"))
        subresource = from_union([from_none, from_str], obj.get("subresource"))
        url = from_union([from_none, from_str], obj.get("url"))
        use_default = from_union([from_bool, from_none], obj.get("useDefault"))
        return Resource(
            resource_id,
            attrs,
            auth_id,
            days,
            dictify,
            documentation_url,
            dump_data,
            end,
            eof,
            example,
            fields,
            filter,
            headers,
            hidden,
            id_field,
            methods,
            name_field,
            note,
            params,
            parent,
            pos,
            resource_name,
            result_key,
            rid,
            srid,
            start,
            subkey,
            subresource,
            url,
            use_default,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["resourceId"] = from_str(self.resource_id)
        result["attrs"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.attrs,
        )
        result["authId"] = from_union([from_none, from_str], self.auth_id)
        result["days"] = from_union([to_float, from_none], self.days)
        result["dictify"] = from_union([from_bool, from_none], self.dictify)
        result["documentationURL"] = from_union(
            [from_none, from_str], self.documentation_url
        )
        result["dumpData"] = from_union([from_bool, from_none], self.dump_data)
        result["end"] = from_union([lambda x: x.isoformat(), from_none], self.end)
        result["eof"] = from_union([from_bool, from_none], self.eof)
        result["example"] = from_union([from_none, from_str], self.example)
        result["fields"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.fields
        )
        result["filter"] = from_union(
            [lambda x: to_class(Filter, x), from_none], self.filter
        )
        result["headers"] = from_union(
            [lambda x: to_class(ResourceHeaders, x), from_none], self.headers
        )
        result["hidden"] = from_union([from_bool, from_none], self.hidden)
        result["idField"] = from_union([from_none, from_str], self.id_field)
        result["methods"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.methods
        )
        result["nameField"] = from_union([from_none, from_str], self.name_field)
        result["note"] = from_union([from_none, from_str], self.note)
        result["params"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.params,
        )
        result["parent"] = from_union([from_none, from_str], self.parent)
        result["pos"] = from_union([to_float, from_none], self.pos)
        result["resourceName"] = from_union([from_none, from_str], self.resource_name)
        result["resultKey"] = from_union([from_none, from_str], self.result_key)
        result["rid"] = from_union([from_none, from_str], self.rid)
        result["srid"] = from_union([from_none, from_str], self.srid)
        result["start"] = from_union([lambda x: x.isoformat(), from_none], self.start)
        result["subkey"] = from_union([from_none, from_str], self.subkey)
        result["subresource"] = from_union([from_none, from_str], self.subresource)
        result["url"] = from_union([from_none, from_str], self.url)
        result["useDefault"] = from_union([from_bool, from_none], self.use_default)
        return result


@dataclass
class StatusResourceClass:
    """The resource represented by the statusResourceId

    An API status resource

    An API resource
    """

    """Unique identifier for the API resource"""
    resource_id: str
    attrs: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """The authorization object used to authenticate"""
    auth_id: Optional[str]
    """The the number of days to fetch data for"""
    days: Optional[float]
    """Convert response to a dictionary"""
    dictify: Optional[bool]
    """URL to API resource documentation"""
    documentation_url: Optional[str]
    """`json.dumps` data for POST/PATCH requests"""
    dump_data: Optional[bool]
    """The last date to fetch data for (defaults to today)"""
    end: Optional[datetime]
    """Is resource at the end of the stream?"""
    eof: Optional[bool]
    """An example API request"""
    example: Optional[str]
    """Resource fields to save from the parsed API response"""
    fields: Optional[List[str]]
    """description"""
    filter: Optional[Filter]
    """HTTP headers to include with requests (case sensitive)"""
    headers: Optional[ResourceHeaders]
    """Hide the resource from"""
    hidden: Optional[bool]
    """Field representing the resource ID (defaults to first field that equals `id` or ends with
    either `_id` or `Id`)
    """
    id_field: Optional[str]
    """HTTP methods this resource allows"""
    methods: Optional[List[str]]
    """Field representing the resource name (defaults to first field that equals or ends with
    `name`)
    """
    name_field: Optional[str]
    """Space to document API inconsistencies"""
    note: Optional[str]
    params: Optional[Dict[str, Union[List[str], bool, AttrClass, int, None, str]]]
    """resourceId of the base resource object"""
    parent: Optional[str]
    """Starting position item to fetch"""
    pos: Optional[float]
    """What the resource is named in the API URL (defaults to `resourceId`)"""
    resource_name: Optional[str]
    """The path to extract from the parsed API response (should return a list of items)"""
    result_key: Optional[str]
    """Currently active resource"""
    rid: Optional[str]
    """Currently active sub resource"""
    srid: Optional[str]
    """The first date to fetch data from"""
    start: Optional[datetime]
    """The path to extract from the parsed API response (should return a list of items)"""
    subkey: Optional[str]
    """What the sub resource is named in the API URL"""
    subresource: Optional[str]
    """The url of a resource endpoint"""
    url: Optional[str]
    """Use default"""
    use_default: Optional[bool]

    @staticmethod
    def from_dict(obj: Any) -> "StatusResourceClass":
        assert isinstance(obj, dict)
        resource_id = from_str(obj.get("resourceId"))
        attrs = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("attrs"),
        )
        auth_id = from_union([from_none, from_str], obj.get("authId"))
        days = from_union([from_float, from_none], obj.get("days"))
        dictify = from_union([from_bool, from_none], obj.get("dictify"))
        documentation_url = from_union(
            [from_none, from_str], obj.get("documentationURL")
        )
        dump_data = from_union([from_bool, from_none], obj.get("dumpData"))
        end = from_union([from_datetime, from_none], obj.get("end"))
        eof = from_union([from_bool, from_none], obj.get("eof"))
        example = from_union([from_none, from_str], obj.get("example"))
        fields = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("fields")
        )
        filter = from_union([Filter.from_dict, from_none], obj.get("filter"))
        headers = from_union([ResourceHeaders.from_dict, from_none], obj.get("headers"))
        hidden = from_union([from_bool, from_none], obj.get("hidden"))
        id_field = from_union([from_none, from_str], obj.get("idField"))
        methods = from_union(
            [lambda x: from_list(from_str, x), from_none], obj.get("methods")
        )
        name_field = from_union([from_none, from_str], obj.get("nameField"))
        note = from_union([from_none, from_str], obj.get("note"))
        params = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            AttrClass.from_dict,
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            obj.get("params"),
        )
        parent = from_union([from_none, from_str], obj.get("parent"))
        pos = from_union([from_float, from_none], obj.get("pos"))
        resource_name = from_union([from_none, from_str], obj.get("resourceName"))
        result_key = from_union([from_none, from_str], obj.get("resultKey"))
        rid = from_union([from_none, from_str], obj.get("rid"))
        srid = from_union([from_none, from_str], obj.get("srid"))
        start = from_union([from_datetime, from_none], obj.get("start"))
        subkey = from_union([from_none, from_str], obj.get("subkey"))
        subresource = from_union([from_none, from_str], obj.get("subresource"))
        url = from_union([from_none, from_str], obj.get("url"))
        use_default = from_union([from_bool, from_none], obj.get("useDefault"))
        return StatusResourceClass(
            resource_id,
            attrs,
            auth_id,
            days,
            dictify,
            documentation_url,
            dump_data,
            end,
            eof,
            example,
            fields,
            filter,
            headers,
            hidden,
            id_field,
            methods,
            name_field,
            note,
            params,
            parent,
            pos,
            resource_name,
            result_key,
            rid,
            srid,
            start,
            subkey,
            subresource,
            url,
            use_default,
        )

    def to_dict(self) -> dict:
        result: dict = {}
        result["resourceId"] = from_str(self.resource_id)
        result["attrs"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.attrs,
        )
        result["authId"] = from_union([from_none, from_str], self.auth_id)
        result["days"] = from_union([to_float, from_none], self.days)
        result["dictify"] = from_union([from_bool, from_none], self.dictify)
        result["documentationURL"] = from_union(
            [from_none, from_str], self.documentation_url
        )
        result["dumpData"] = from_union([from_bool, from_none], self.dump_data)
        result["end"] = from_union([lambda x: x.isoformat(), from_none], self.end)
        result["eof"] = from_union([from_bool, from_none], self.eof)
        result["example"] = from_union([from_none, from_str], self.example)
        result["fields"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.fields
        )
        result["filter"] = from_union(
            [lambda x: to_class(Filter, x), from_none], self.filter
        )
        result["headers"] = from_union(
            [lambda x: to_class(ResourceHeaders, x), from_none], self.headers
        )
        result["hidden"] = from_union([from_bool, from_none], self.hidden)
        result["idField"] = from_union([from_none, from_str], self.id_field)
        result["methods"] = from_union(
            [lambda x: from_list(from_str, x), from_none], self.methods
        )
        result["nameField"] = from_union([from_none, from_str], self.name_field)
        result["note"] = from_union([from_none, from_str], self.note)
        result["params"] = from_union(
            [
                lambda x: from_dict(
                    lambda x: from_union(
                        [
                            lambda x: from_list(from_str, x),
                            from_bool,
                            lambda x: to_class(AttrClass, x),
                            from_int,
                            from_none,
                            from_str,
                        ],
                        x,
                    ),
                    x,
                ),
                from_none,
            ],
            self.params,
        )
        result["parent"] = from_union([from_none, from_str], self.parent)
        result["pos"] = from_union([to_float, from_none], self.pos)
        result["resourceName"] = from_union([from_none, from_str], self.resource_name)
        result["resultKey"] = from_union([from_none, from_str], self.result_key)
        result["rid"] = from_union([from_none, from_str], self.rid)
        result["srid"] = from_union([from_none, from_str], self.srid)
        result["start"] = from_union([lambda x: x.isoformat(), from_none], self.start)
        result["subkey"] = from_union([from_none, from_str], self.subkey)
        result["subresource"] = from_union([from_none, from_str], self.subresource)
        result["url"] = from_union([from_none, from_str], self.url)
        result["useDefault"] = from_union([from_bool, from_none], self.use_default)
        return result


@dataclass
class Provider:
    """A 3rd party API provider"""

    """Authentication methods accepted by API provider"""
    auths: List[Authentication]
    """Unique API provider identifier"""
    prefix: str
    """Resources exposed by 3rd party API"""
    resources: List[Resource]
    """The resource represented by the statusResourceId"""
    status_resource: Optional[StatusResourceClass]
    """The resourceId of a resource to redirect to after authenticating the user"""
    status_resource_id: Optional[str]

    @staticmethod
    def from_dict(obj: Any) -> "Provider":
        assert isinstance(obj, dict)
        auths = from_list(Authentication.from_dict, obj.get("auths"))
        prefix = from_str(obj.get("prefix"))
        resources = from_list(Resource.from_dict, obj.get("resources"))
        status_resource = from_union(
            [StatusResourceClass.from_dict, from_none], obj.get("statusResource")
        )
        status_resource_id = from_union(
            [from_none, from_str], obj.get("statusResourceId")
        )
        return Provider(auths, prefix, resources, status_resource, status_resource_id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["auths"] = from_list(lambda x: to_class(Authentication, x), self.auths)
        result["prefix"] = from_str(self.prefix)
        result["resources"] = from_list(lambda x: to_class(Resource, x), self.resources)
        result["statusResource"] = from_union(
            [lambda x: to_class(StatusResourceClass, x), from_none],
            self.status_resource,
        )
        result["statusResourceId"] = from_union(
            [from_none, from_str], self.status_resource_id
        )
        return result


def provider_from_dict(s: Any) -> Provider:
    return Provider.from_dict(s)


def provider_to_dict(x: Provider) -> Any:
    return to_class(Provider, x)
