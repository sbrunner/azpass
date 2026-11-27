# Copyright (c) 2026, Stéphane Brunner

"""
The answers of Azure that are worth remembering between two runs.

Two files are used, both created with the owner permissions only:

- ``$XDG_CONFIG_HOME/azpass/state.json`` with the last subscription used and the
  URL of the key vaults already resolved, no secret at all.
- ``$XDG_CACHE_HOME/azpass/tokens.json`` with the bearer tokens, which are written
  in clear text and expire on their own.
"""

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Final, TypedDict

from azure.core.credentials import AccessToken

STATE_VARIABLE: Final = "XDG_CONFIG_HOME"
CACHE_VARIABLE: Final = "XDG_CACHE_HOME"
DIRECTORY: Final = "azpass"
STATE_FILE: Final = "state.json"
TOKENS_FILE: Final = "tokens.json"
EXPIRY_MARGIN: Final = 300
DEFAULT_CONFIG: Final = ".config"
DEFAULT_CACHE: Final = ".cache"


class State(TypedDict, total=False):
    """What is remembered between two runs."""

    subscription: str
    vaults: dict[str, str]


class CachedToken(TypedDict):
    """A bearer token read from the cache."""

    token: str
    expires_on: int


def base_directory(variable: str, default: str) -> Path:
    """
    Return the base directory of a kind of file.

    :param variable: The environment variable giving the directory.
    :param default: The directory under the home, when the variable is unset.
    :return: The absolute path of the base directory.
    """
    from_environment = os.environ.get(variable)
    if from_environment:
        return Path(from_environment)
    return Path.home() / default


def state_file() -> Path:
    """
    Return the path of the state file.

    :return: The absolute path of the file.
    """
    return base_directory(STATE_VARIABLE, DEFAULT_CONFIG) / DIRECTORY / STATE_FILE


def tokens_file() -> Path:
    """
    Return the path of the token cache file.

    :return: The absolute path of the file.
    """
    return base_directory(CACHE_VARIABLE, DEFAULT_CACHE) / DIRECTORY / TOKENS_FILE


def read_json(path: Path) -> dict[str, Any]:
    """
    Read a JSON object, an unavailable file being an empty object.

    A cache must never break the command line, a file that we cannot read, that we
    cannot parse or that does not contain an object is simply a cache miss.

    :param path: The file to read.
    :return: The content of the file, empty when unusable.
    """
    try:
        with path.open(encoding="utf-8") as json_file:
            content = json.load(json_file)
    except (OSError, ValueError):
        return {}
    return content if isinstance(content, dict) else {}


def read_state(path: Path) -> State:
    """
    Read the state file, keeping only what has the expected type.

    :param path: The file to read.
    :return: The cached state.
    """
    content = read_json(path)
    state: State = {}
    subscription = content.get("subscription")
    vaults = content.get("vaults")
    if isinstance(subscription, str):
        state["subscription"] = subscription
    if isinstance(vaults, dict) and all(
        isinstance(name, str) and isinstance(url, str) for name, url in vaults.items()
    ):
        state["vaults"] = vaults
    return state


def read_tokens(path: Path) -> dict[str, CachedToken]:
    """
    Read the token file, keeping only what has the expected type.

    :param path: The file to read.
    :return: The cached tokens, by scope.
    """
    tokens: dict[str, CachedToken] = {}
    for scopes, content in read_json(path).items():
        if not isinstance(scopes, str) or not isinstance(content, dict):
            continue
        token = content.get("token")
        expires_on = content.get("expires_on")
        if isinstance(token, str) and isinstance(expires_on, int):
            tokens[scopes] = {"token": token, "expires_on": expires_on}
    return tokens


def write_json(path: Path, content: dict[str, Any]) -> None:
    """
    Write a JSON object, atomically and for the owner only.

    :param path: The file to write.
    :param content: The content to store.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkstemp creates the file with the owner permissions, what a token needs.
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp", suffix=".json")
    partial = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(content, handle, indent=2, sort_keys=True)
        partial.replace(path)
    except BaseException:
        # A partial file would be read as a wrong answer of Azure later.
        partial.unlink(missing_ok=True)
        raise


class Cache:
    """The answers of Azure that were already read from the disk."""

    def __init__(self, enabled: bool = True) -> None:
        """
        Initialize.

        :param enabled: Whether the cache is read and written.
        """
        self.enabled = enabled
        self.used = False
        self._state = read_state(state_file()) if enabled else State()
        self._tokens = read_tokens(tokens_file()) if enabled else {}

    def subscription(self) -> str | None:
        """
        Return the last subscription used.

        :return: The identifier of the subscription, ``None`` when unknown.
        """
        if not self.enabled:
            return None
        subscription = self._state.get("subscription")
        if subscription is not None:
            self.used = True
        return subscription

    def remember_subscription(self, subscription: str) -> None:
        """
        Remember the subscription that has just been used.

        :param subscription: The identifier of the subscription.
        """
        if not self.enabled or self._state.get("subscription") == subscription:
            return
        self._state["subscription"] = subscription
        write_json(state_file(), dict(self._state))

    def vault_url(self, vault: str) -> str | None:
        """
        Return the URL of a key vault already resolved.

        :param vault: The name of the key vault.
        :return: The URL of the key vault, ``None`` when unknown.
        """
        if not self.enabled:
            return None
        url = self._state.get("vaults", {}).get(vault)
        if url is not None:
            self.used = True
        return url

    def remember_vault_url(self, vault: str, url: str) -> None:
        """
        Remember the URL of a key vault.

        The name of a key vault is unique in Azure, the subscription is not needed
        to key the URL, and a name used again after a purge is covered by the retry.

        :param vault: The name of the key vault.
        :param url: The URL of the key vault.
        """
        if not self.enabled:
            return
        vaults = self._state.setdefault("vaults", {})
        if vaults.get(vault) == url:
            return
        vaults[vault] = url
        write_json(state_file(), dict(self._state))

    def token(self, scopes: str) -> AccessToken | None:
        """
        Return a token that is still valid for long enough.

        :param scopes: The scopes the token is given for.
        :return: The token, ``None`` when it is absent or about to expire.
        """
        if not self.enabled:
            return None
        cached = self._tokens.get(scopes)
        if cached is None or cached["expires_on"] - EXPIRY_MARGIN < time.time():
            return None
        self.used = True
        return AccessToken(cached["token"], cached["expires_on"])

    def remember_token(self, scopes: str, token: AccessToken) -> None:
        """
        Remember a token until it expires.

        :param scopes: The scopes the token was given for.
        :param token: The token to store.
        """
        if not self.enabled:
            return
        self._tokens[scopes] = {"token": token.token, "expires_on": token.expires_on}
        write_json(tokens_file(), dict(self._tokens))

    def forget(self, vault: str | None) -> None:
        """
        Drop everything that can explain a refusal of Azure.

        The subscription itself is forgotten, a vault not found where we expected
        it means that our view of the account is not the good one any more.

        :param vault: The key vault whose URL has to be forgotten, if any.
        """
        self.used = False
        if not self.enabled:
            return
        self._state.pop("subscription", None)
        vaults = self._state.get("vaults")
        if vaults is not None:
            if vault is not None:
                vaults.pop(vault, None)
            if not vaults:
                # An empty dictionary is not worth keeping in the file.
                del self._state["vaults"]
        write_json(state_file(), dict(self._state))
        self._tokens = {}
        tokens_file().unlink(missing_ok=True)
