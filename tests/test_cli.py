# Copyright (c) 2026, Stéphane Brunner

"""Tests of the command line."""

import json
import logging
import shlex
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import AzureError, HttpResponseError

from azpass import cli, state

CREATED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
UPDATED = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
DELETED = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
VAULT_URL = "https://my-kv.vault.azure.net/"

CREATED_EPOCH = 1767323045
UPDATED_EPOCH = 1770091506
DELETED_EPOCH = 1772600767
SECRET_ID = "https://my-kv.vault.azure.net/secrets/db/version"
STALE_URL = "https://old.my-kv.vault.azure.net/"
TOKEN_VALUE = "aaaa"


@dataclass
class FakeProperties:
    """A fake ``SecretProperties``."""

    id: str = "https://my-kv.vault.azure.net/secrets/db"
    name: str = "db"
    enabled: bool = True
    created_on: datetime = CREATED
    updated_on: datetime = UPDATED
    expires_on: datetime | None = None
    recovery_level: str = "Recoverable+Purgeable"
    recoverable_days: int = 90
    managed: bool = False
    tags: dict[str, str] | None = None


@dataclass
class FakeSecret:
    """A fake ``KeyVaultSecret``."""

    id: str = SECRET_ID
    properties: FakeProperties = field(default_factory=FakeProperties)
    value: str = "hunter2"


@dataclass
class FakeDeletedSecret:
    """A fake ``DeletedSecret``."""

    id: str = "https://my-kv.vault.azure.net/deletedsecrets/db"
    properties: FakeProperties = field(default_factory=FakeProperties)
    recovery_id: str = "https://my-kv.vault.azure.net/deletedsecrets/db"
    deleted_date: datetime = DELETED
    scheduled_purge_date: datetime = DELETED


@dataclass
class FakePoller:
    """A fake poller of a delete operation."""

    secret: FakeDeletedSecret = field(default_factory=FakeDeletedSecret)

    def result(self) -> FakeDeletedSecret:
        """Return the deleted secret."""
        return self.secret


@dataclass
class FakeVaultProperties:
    """A fake ``VaultProperties``."""

    vault_uri: str = VAULT_URL


@dataclass
class FakeVault:
    """A fake ``Vault``."""

    name: str = "my-kv"
    resource_group: str = "my-rg"
    properties: FakeVaultProperties = field(default_factory=FakeVaultProperties)
    location: str = "westeurope"
    tags: dict[str, str] | None = None

    @property
    def id(self) -> str:
        """The ARM identifier of the vault."""
        return (
            f"/subscriptions/sub-1/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.KeyVault/vaults/{self.name}"
        )

    def as_dict(self) -> dict:
        """Return the REST representation of the vault."""
        return {
            "id": self.id,
            "name": self.name,
            "location": self.location,
            "tags": self.tags,
            "properties": {
                "vaultUri": self.properties.vault_uri,
                "sku": {"family": "A", "name": "standard"},
            },
        }


class FakeStdin:
    """A fake standard input."""

    def __init__(self, value: str, tty: bool = False) -> None:
        self.value = value
        self.tty = tty
        self.reads = 0

    def read(self) -> str:
        """Read the value."""
        self.reads += 1
        return self.value

    def isatty(self) -> bool:
        """Tell if the input is a terminal."""
        return self.tty


@dataclass
class FakeSubscription:
    """A fake ``Subscription``."""

    subscription_id: str = "sub-1"
    display_name: str = "My subscription"
    state: str | None = "Enabled"


class FakeSecretClient:
    """A fake ``SecretClient`` recording the calls."""

    calls: list = []
    set_values: list = []

    def __init__(self, vault_url: str, credential: object) -> None:
        FakeSecretClient.calls.append((vault_url, credential))
        self.vault_url = vault_url

    def list_properties_of_secrets(self) -> list[FakeProperties]:
        """Return the secrets."""
        return [FakeProperties(), FakeProperties(name="other")]

    def get_secret(self, name: str) -> FakeSecret:
        """Return a secret."""
        assert name == "db"
        return FakeSecret()

    def set_secret(self, name: str, value: str) -> FakeSecret:
        """Set a secret."""
        assert name == "db"
        FakeSecretClient.set_values.append(value)
        return FakeSecret(value=value)

    def begin_delete_secret(self, name: str) -> FakePoller:
        """Delete a secret."""
        assert name == "db"
        return FakePoller()


class InterruptedSecretClient(FakeSecretClient):
    """A fake ``SecretClient`` interrupted by the user."""

    def get_secret(self, name: str) -> FakeSecret:
        """Raise the interruption of the user."""
        raise KeyboardInterrupt


class FakeResponse:
    """A fake HTTP response, enough for ``HttpResponseError``."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.reason = "Nope"

    def text_content(self) -> None:
        """Return no body."""
        return None


class StaleUrlSecretClient(FakeSecretClient):
    """A fake ``SecretClient`` refusing the URL it was given once."""

    failures = 1

    def __init__(self, vault_url: str, credential: object) -> None:
        super().__init__(vault_url, credential)
        if StaleUrlSecretClient.failures > 0:
            StaleUrlSecretClient.failures -= 1
            raise HttpResponseError("Not Found", response=FakeResponse(404))


class RejectingSecretClient(FakeSecretClient):
    """A fake ``SecretClient`` always refusing."""

    def __init__(self, vault_url: str, credential: object) -> None:
        super().__init__(vault_url, credential)
        raise HttpResponseError("Not Found", response=FakeResponse(404))


class FakeCredential:
    """A fake credential counting the token requests."""

    def __init__(self, value: str = TOKEN_VALUE, expires_on: int = 9999999999) -> None:
        self.calls: list = []
        self.value = value
        self.expires_on = expires_on

    def get_token(self, *scopes: str, **kwargs: object):
        """Return a token."""
        self.calls.append(scopes)
        return AccessToken(self.value, self.expires_on)

    def close(self) -> None:
        """Close."""


class FakeStderr:
    """A fake standard error."""

    def __init__(self, tty: bool = True) -> None:
        self.written: list = []
        self.tty = tty

    def isatty(self) -> bool:
        """Tell if the output is a terminal."""
        return self.tty

    def write(self, text: str) -> None:
        """Write a message."""
        self.written.append(text)

    def flush(self) -> None:
        """Flush."""


class FakeVaultsOperations:
    """A fake ``vaults`` operation."""

    def __init__(self, vaults: list[FakeVault], error: Exception | None = None) -> None:
        self.vaults = vaults
        self.error = error

    def list_by_subscription(self) -> list[FakeVault]:
        """Return the vaults."""
        if self.error is not None:
            raise self.error
        return self.vaults


class FakeKeyVaultManagementClient:
    """A fake ``KeyVaultManagementClient``."""

    vaults: FakeVaultsOperations = FakeVaultsOperations([FakeVault()])
    subscriptions: list[str] = []

    def __init__(self, credential: object, subscription_id: str) -> None:
        FakeKeyVaultManagementClient.subscriptions.append(subscription_id)
        self.vaults = FakeKeyVaultManagementClient.vaults


class FakeSubscriptionsOperations:
    """A fake ``subscriptions`` operation."""

    subscriptions: list[FakeSubscription] = []

    def list(self) -> list[FakeSubscription]:
        """Return the subscriptions."""
        return FakeSubscriptionsOperations.subscriptions


class FakeSubscriptionClient:
    """A fake ``SubscriptionClient``."""

    def __init__(self, credential: object) -> None:
        self.subscriptions = FakeSubscriptionsOperations()


@pytest.fixture
def xdg(monkeypatch, tmp_path):
    """Put the cache files in a temporary directory, never in the home."""
    monkeypatch.setenv(state.STATE_VARIABLE, str(tmp_path / "config"))
    monkeypatch.setenv(state.CACHE_VARIABLE, str(tmp_path / "cache"))
    return tmp_path


@pytest.fixture
def azure(xdg, monkeypatch, capsys):
    """Patch all the Azure entry points and put the caches in a temporary directory."""
    FakeSecretClient.calls = []
    FakeSecretClient.set_values = []
    FakeKeyVaultManagementClient.vaults = FakeVaultsOperations([FakeVault()])
    FakeKeyVaultManagementClient.subscriptions = []
    FakeSubscriptionsOperations.subscriptions = [FakeSubscription()]
    monkeypatch.setattr(cli, "SecretClient", FakeSecretClient)
    monkeypatch.setattr(cli, "KeyVaultManagementClient", FakeKeyVaultManagementClient)
    monkeypatch.setattr(cli, "SubscriptionClient", FakeSubscriptionClient)
    monkeypatch.setattr(cli, "DefaultAzureCredential", lambda: "credential")
    monkeypatch.delenv(cli.SUBSCRIPTION_ENV_VAR, raising=False)
    return capsys


def test_dry_run_vaults(azure):
    """The dry run prints the az command listing the key vaults."""
    assert cli.main(["--dry-run"]) == 0
    assert azure.readouterr().out == (
        "az keyvault list "
        "--query '[].{name:name,rg:resourceGroup,url:properties.vaultUri}' "
        "--output tsv --subscription '<subscription>'\n"
    )


def test_dry_run_never_calls_azure(azure, monkeypatch):
    """The dry run does not even create a client."""

    def boom(*args, **kwargs):
        raise AssertionError("Azure must not be called on a dry run")

    monkeypatch.setattr(cli, "SecretClient", boom)
    monkeypatch.setattr(cli, "KeyVaultManagementClient", boom)
    monkeypatch.setattr(cli, "SubscriptionClient", boom)
    monkeypatch.setattr(cli, "DefaultAzureCredential", boom)
    for argv in (["--dry-run"], ["my-kv", "--dry-run"], ["my-kv", "db", "--dry-run"]):
        assert cli.main(argv) == 0
    assert cli.main(["my-kv", "--set", "db", "--dry-run"]) == 0
    assert cli.main(["my-kv", "--rm", "db", "--dry-run"]) == 0
    azure.readouterr()


def test_dry_run_does_not_read_the_standard_input(azure, monkeypatch):
    """The dry run of a set does not consume the standard input."""
    stdin = FakeStdin("hunter2")
    monkeypatch.setattr(cli.sys, "stdin", stdin)
    assert cli.main(["my-kv", "--set", "db", "--dry-run"]) == 0
    assert stdin.reads == 0


def test_dry_run_all_operations(azure):
    """The dry run prints the az command of every operation."""
    assert cli.main(["my-kv", "--dry-run"]) == 0
    assert cli.main(["my-kv", "db", "--dry-run"]) == 0
    assert cli.main(["my-kv", "--rm", "db", "--dry-run"]) == 0
    commands = azure.readouterr().out.splitlines()
    assert commands == [
        "az keyvault secret list --vault-name my-kv --query '[].name' --output tsv",
        "az keyvault secret show --vault-name my-kv --name db --query value --output tsv",
        "az keyvault secret delete --vault-name my-kv --name db --query id --output tsv",
    ]


def test_dry_run_json(azure):
    """The JSON output drops the query of the az command."""
    assert cli.main(["my-kv", "db", "--json", "--dry-run"]) == 0
    assert azure.readouterr().out == ("az keyvault secret show --vault-name my-kv --name db --output json\n")


def test_dry_run_subscription(azure, monkeypatch):
    """A known subscription is passed to the az command."""
    monkeypatch.setenv(cli.SUBSCRIPTION_ENV_VAR, "sub-env")
    assert cli.main(["my-kv", "db", "--dry-run"]) == 0
    assert cli.main(["--dry-run"]) == 0
    lines = azure.readouterr().out.splitlines()
    assert lines[0].startswith("az --subscription sub-env keyvault secret show")
    assert lines[1].endswith("--subscription sub-env")


def test_dry_run_hides_the_value(azure, monkeypatch):
    """The value of a secret is never printed by the dry run."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin("top secret"))
    assert cli.main(["my-kv", "--set", "db", "--dry-run"]) == 0
    out = azure.readouterr().out
    assert "top secret" not in out
    assert out == (
        "az keyvault secret set --vault-name my-kv --name db --value '<hidden>' --query id --output tsv\n"
    )


def test_list_vaults(azure):
    """The key vaults are listed with their resource group and their URL."""
    assert cli.main([]) == 0
    assert azure.readouterr().out == f"my-kv\tmy-rg\t{VAULT_URL}\n"
    assert FakeKeyVaultManagementClient.subscriptions == ["sub-1"]


def test_list_vaults_json(azure):
    """The JSON output of the key vaults holds the management properties."""
    assert cli.main(["--json"]) == 0
    vaults = json.loads(azure.readouterr().out)
    assert vaults[0]["name"] == "my-kv"
    assert vaults[0]["sku"] == {"family": "A", "name": "standard"}
    assert vaults[0]["resourceGroup"] == "my-rg"
    assert vaults[0]["properties"]["vaultUri"] == VAULT_URL


def test_list_secrets(azure):
    """The secrets of a key vault are listed by name."""
    assert cli.main(["my-kv"]) == 0
    assert azure.readouterr().out == "db\nother\n"
    assert len(FakeSecretClient.calls) == 1
    vault_url, credential = FakeSecretClient.calls[0]
    assert vault_url == VAULT_URL
    assert isinstance(credential, cli.CachingCredential)
    assert credential.fallback == "credential"


def test_list_secrets_json(azure):
    """The JSON output of the secrets never holds a value."""
    assert cli.main(["my-kv", "--json"]) == 0
    secrets = json.loads(azure.readouterr().out)
    assert len(secrets) == 2
    assert secrets[0]["id"] == "https://my-kv.vault.azure.net/secrets/db"
    assert secrets[0]["attributes"] == {
        "enabled": True,
        "created": CREATED_EPOCH,
        "updated": UPDATED_EPOCH,
        "expires": None,
        "recoveryLevel": "Recoverable+Purgeable",
        "recoverableDays": 90,
        "managed": False,
    }
    assert "value" not in secrets[0]


def test_get_secret(azure):
    """The value of a secret is printed."""
    assert cli.main(["my-kv", "db"]) == 0
    assert azure.readouterr().out == "hunter2\n"


def test_get_secret_json(azure):
    """The JSON output of a secret holds its value."""
    assert cli.main(["my-kv", "db", "--json"]) == 0
    assert json.loads(azure.readouterr().out) == {
        "id": "https://my-kv.vault.azure.net/secrets/db/version",
        "attributes": {
            "enabled": True,
            "created": CREATED_EPOCH,
            "updated": UPDATED_EPOCH,
            "expires": None,
            "recoveryLevel": "Recoverable+Purgeable",
            "recoverableDays": 90,
            "managed": False,
        },
        "tags": None,
        "value": "hunter2",
    }


def test_set_secret_reads_the_standard_input(azure, monkeypatch):
    """The value of the secret comes from a pipe, the identifier is printed."""
    stdin = FakeStdin("hunter2\n")
    monkeypatch.setattr(cli.sys, "stdin", stdin)
    assert cli.main(["my-kv", "--set", "db"]) == 0
    assert azure.readouterr().out == f"{SECRET_ID}\n"
    assert stdin.reads == 1


def test_set_secret_keeps_the_inner_ends_of_line(azure, monkeypatch):
    """Only one trailing end of line is dropped, the read value is the sent one."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin("a\nb\n\n"))
    assert cli.main(["my-kv", "--set", "db"]) == 0
    azure.readouterr()
    assert FakeSecretClient.set_values == ["a\nb\n"]


def test_set_secret_asks_the_value_on_a_terminal(azure, monkeypatch):
    """On a terminal the value is asked without echo, no read is done."""
    stdin = FakeStdin("", tty=True)
    prompts = []

    def fake_getpass(prompt, stream):
        prompts.append((prompt, stream))
        return "hunter2"

    monkeypatch.setattr(cli.sys, "stdin", stdin)
    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)
    assert cli.main(["my-kv", "--set", "db"]) == 0
    assert azure.readouterr().out == f"{SECRET_ID}\n"
    assert prompts == [("azpass: value of the secret 'db' in 'my-kv': ", cli.sys.stderr)]
    assert stdin.reads == 0


def test_set_secret_interruption_on_a_terminal(azure, monkeypatch):
    """Interrupting the value prompt does not print a traceback."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin("", tty=True))

    def fake_getpass(prompt, stream):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)
    assert cli.main(["my-kv", "--set", "db"]) == 130
    captured = azure.readouterr()
    assert captured.out == ""
    assert captured.err == "azpass: interrupted\n"


def test_set_secret_end_of_file_on_a_terminal(azure, monkeypatch):
    """The Ctrl-D given at the prompt is an empty value, not a traceback."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin("", tty=True))

    def fake_getpass(prompt, stream):
        raise EOFError

    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)
    assert cli.main(["my-kv", "--set", "db"]) == 2
    captured = azure.readouterr()
    assert captured.out == ""
    assert captured.err == "azpass: error: no value on the terminal\n"


def test_interruption_during_a_call(azure, monkeypatch):
    """Interrupting a request does not print a traceback either."""
    monkeypatch.setattr(cli, "SecretClient", InterruptedSecretClient)
    assert cli.main(["my-kv", "db"]) == 130
    assert azure.readouterr().err == "azpass: interrupted\n"


def test_set_secret_without_value(azure, monkeypatch):
    """An empty standard input is an error."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin(""))
    assert cli.main(["my-kv", "--set", "db"]) == 2
    assert azure.readouterr().err == "azpass: error: no value on the standard input\n"


def test_rm_secret(azure):
    """The identifier of the deleted secret is printed."""
    assert cli.main(["my-kv", "--rm", "db"]) == 0
    assert azure.readouterr().out == ("https://my-kv.vault.azure.net/deletedsecrets/db\n")


def test_rm_secret_json(azure):
    """The JSON output of the deletion holds the recovery information."""
    assert cli.main(["my-kv", "--rm", "db", "--json"]) == 0
    deleted = json.loads(azure.readouterr().out)
    assert deleted["recoveryId"] == "https://my-kv.vault.azure.net/deletedsecrets/db"
    assert deleted["deletedDate"] == DELETED_EPOCH
    assert deleted["scheduledPurgeDate"] == DELETED_EPOCH
    assert deleted["tags"] is None


def test_vault_url_explicit(azure):
    """The URL of the key vault can be given."""
    assert cli.main(["my-kv", "db", "--vault-url", "https://other.vault.azure.net/"]) == 0
    azure.readouterr()
    assert FakeSecretClient.calls[-1][0] == "https://other.vault.azure.net/"


def test_vault_url_from_the_management_plane(azure, monkeypatch):
    """The URL of the key vault is read from the management plane."""
    FakeKeyVaultManagementClient.vaults = FakeVaultsOperations(
        [FakeVault(name="other"), FakeVault(properties=FakeVaultProperties("https://my-kv.fr/"))]
    )
    assert cli.main(["my-kv", "db", "--subscription", "sub-1"]) == 0
    azure.readouterr()
    assert FakeSecretClient.calls[-1][0] == "https://my-kv.fr/"


def test_vault_url_without_subscription(azure):
    """Without subscription the classical URL is used, no management call."""
    FakeKeyVaultManagementClient.vaults = FakeVaultsOperations([], error=AssertionError("must not be called"))
    assert cli.main(["my-kv", "db"]) == 0
    azure.readouterr()
    assert FakeSecretClient.calls[-1][0] == VAULT_URL


def test_vault_url_without_management_rights(azure):
    """The URL is still found when the management plane is not readable."""
    FakeKeyVaultManagementClient.vaults = FakeVaultsOperations([], error=AzureError("Forbidden"))
    assert cli.main(["my-kv", "db", "--subscription", "sub-1"]) == 0
    azure.readouterr()
    assert FakeSecretClient.calls[-1][0] == VAULT_URL


def test_subscription_from_the_command_line(azure):
    """The subscription given on the command line is used."""
    assert cli.main(["--subscription", "sub-9"]) == 0
    azure.readouterr()
    assert FakeKeyVaultManagementClient.subscriptions == ["sub-9"]


def test_subscription_from_the_environment(azure, monkeypatch):
    """The subscription given in the environment is used."""
    monkeypatch.setenv(cli.SUBSCRIPTION_ENV_VAR, "sub-env")
    assert cli.main([]) == 0
    azure.readouterr()
    assert FakeKeyVaultManagementClient.subscriptions == ["sub-env"]


def test_subscription_autodetection(azure):
    """A single accessible subscription is used without being given."""
    assert cli.main([]) == 0
    azure.readouterr()
    assert FakeKeyVaultManagementClient.subscriptions == ["sub-1"]


def test_subscription_ambiguous(azure):
    """Several subscriptions oblige the user to choose."""
    FakeSubscriptionsOperations.subscriptions = [
        FakeSubscription(subscription_id="sub-1"),
        FakeSubscription(subscription_id="sub-2", display_name="Other"),
    ]
    assert cli.main([]) == 2
    assert "use --subscription with one of: sub-1 (My subscription), sub-2 (Other)" in (
        azure.readouterr().err
    )


def test_subscription_disabled(azure):
    """A disabled subscription is not usable."""
    FakeSubscriptionsOperations.subscriptions = [
        FakeSubscription(),
        FakeSubscription(subscription_id="sub-2", state="Disabled"),
    ]
    assert cli.main([]) == 0
    azure.readouterr()
    assert FakeKeyVaultManagementClient.subscriptions == ["sub-1"]


def test_subscription_without_any(azure):
    """No subscription at all is an explicit error."""
    FakeSubscriptionsOperations.subscriptions = []
    assert cli.main([]) == 2
    assert "no accessible subscription" in azure.readouterr().err


def test_azure_error(azure, monkeypatch):
    """An Azure error is printed as a message, not as a traceback."""
    assert cli.main(["--subscription", "sub-1"]) == 0
    azure.readouterr()

    class Failing(FakeKeyVaultManagementClient):
        def __init__(self, credential, subscription_id):
            super().__init__(credential, subscription_id)
            self.vaults = FakeVaultsOperations([], error=AzureError("Forbidden"))

    monkeypatch.setattr(cli, "KeyVaultManagementClient", Failing)
    assert cli.main(["--subscription", "sub-1"]) == 1
    assert azure.readouterr().err == "azpass: error: Forbidden\n"


def test_set_and_key_are_exclusive(azure):
    """The key cannot be given twice."""
    with pytest.raises(SystemExit):
        cli.main(["my-kv", "db", "--set", "db"])


def test_set_and_rm_are_exclusive(azure):
    """The operations cannot be mixed."""
    with pytest.raises(SystemExit):
        cli.main(["my-kv", "--set", "db", "--rm", "other"])


def test_set_without_vault(azure):
    """The vault is mandatory to set a secret."""
    with pytest.raises(SystemExit):
        cli.main(["--set", "db"])


def test_build_az_command_is_shell_joinable():
    """The printed command is exactly the list of arguments."""
    plan: cli.Plan = {
        "operation": "secrets",
        "vault": "my kv",
        "key": None,
        "subscription": None,
        "vault_url": None,
        "json_output": False,
    }
    command = cli.build_az_command(plan)
    assert command == [
        "az",
        "keyvault",
        "secret",
        "list",
        "--vault-name",
        "my kv",
        "--query",
        "[].name",
        "--output",
        "tsv",
    ]
    assert shlex.split(shlex.join(command)) == command


def test_epoch():
    """The dates are converted to the timestamps of the az CLI."""
    assert cli._epoch(CREATED) == CREATED_EPOCH
    assert cli._epoch(None) is None


def test_state_remembered_after_a_run(azure):
    """The subscription and the URLs of the vaults are saved for the next run."""
    assert cli.main(["--subscription", "sub-9"]) == 0
    azure.readouterr()
    content = state.read_json(state.state_file())
    assert content["subscription"] == "sub-9"
    assert content["vaults"] == {"my-kv": VAULT_URL}
    mode = state.state_file().stat().st_mode & 0o777
    assert mode == 0o600


def test_cached_url_skips_the_management_plane(azure):
    """A known vault URL avoids the expensive lookup of the management plane."""
    state.write_json(state.state_file(), {"vaults": {"my-kv": STALE_URL}})
    FakeSecretClient.calls = []
    assert cli.main(["my-kv", "db"]) == 0
    azure.readouterr()
    assert FakeKeyVaultManagementClient.subscriptions == []
    assert FakeSecretClient.calls[0][0] == STALE_URL


def test_cached_subscription_skips_the_lookup(azure):
    """The last subscription used avoids asking the accessible subscriptions."""
    state.write_json(state.state_file(), {"subscription": "sub-cached"})
    assert cli.main([]) == 0
    azure.readouterr()
    assert FakeKeyVaultManagementClient.subscriptions == ["sub-cached"]


def test_no_cache_ignores_the_state(azure):
    """The flag ignores what was remembered, and does not rewrite it."""
    state.write_json(state.state_file(), {"vaults": {"my-kv": STALE_URL}, "subscription": "sub-x"})
    FakeSecretClient.calls = []
    assert cli.main(["my-kv", "db", "--no-cache"]) == 0
    azure.readouterr()
    assert FakeSecretClient.calls[0][0] == VAULT_URL
    assert state.read_json(state.state_file()) == {"vaults": {"my-kv": STALE_URL}, "subscription": "sub-x"}


def test_corrupted_state_is_ignored(azure):
    """A cache file we cannot read is simply a cache miss."""
    state.state_file().parent.mkdir(parents=True, exist_ok=True)
    state.state_file().write_text("{not json at all", encoding="utf-8")
    assert cli.main(["my-kv", "db"]) == 0
    assert azure.readouterr().out == "hunter2\n"


def test_wrong_types_in_state_are_ignored(azure):
    """A cache file containing anything does not break the types of the tool."""
    state.write_json(state.state_file(), {"subscription": 3, "vaults": {"my-kv": 42}})
    assert cli.main(["my-kv", "db"]) == 0
    assert azure.readouterr().out == "hunter2\n"


def test_stale_url_is_retried_once(azure, monkeypatch):
    """A refusal of Azure drops the cached answers and is tried once again."""
    StaleUrlSecretClient.failures = 1
    state.write_json(state.state_file(), {"vaults": {"my-kv": STALE_URL}, "subscription": "sub-cached"})
    monkeypatch.setattr(cli, "SecretClient", StaleUrlSecretClient)
    FakeSecretClient.calls = []
    assert cli.main(["my-kv", "db"]) == 0
    azure.readouterr()
    assert [call[0] for call in FakeSecretClient.calls] == [STALE_URL, VAULT_URL]
    assert state.read_json(state.state_file()) == {}


def test_error_without_cached_answer_is_not_retried(azure, monkeypatch):
    """Nothing is tried twice when no cached value was used."""
    monkeypatch.setattr(cli, "SecretClient", RejectingSecretClient)
    FakeSecretClient.calls = []
    assert cli.main(["my-kv", "db"]) == 1
    assert "azpass: error: Not Found" in azure.readouterr().err
    assert len(FakeSecretClient.calls) == 1


def test_token_cache_avoids_the_credential(xdg):
    """A token which is still valid is read from the disk, not asked again."""
    credential = FakeCredential()
    caching = cli.CachingCredential(state.Cache(True), credential)
    assert caching.get_token("https://vault.azure.net/.default").token == TOKEN_VALUE
    assert caching.get_token("https://vault.azure.net/.default").token == TOKEN_VALUE
    assert len(credential.calls) == 1
    other = cli.CachingCredential(state.Cache(True), FakeCredential())
    assert other.get_token("https://vault.azure.net/.default").token == TOKEN_VALUE
    assert state.tokens_file().exists()
    assert state.tokens_file().stat().st_mode & 0o777 == 0o600


def test_expired_token_is_asked_again(xdg):
    """A token close to its expiry is not used."""
    cache = state.Cache(True)
    soon = int(datetime.now(UTC).timestamp()) + state.EXPIRY_MARGIN - 60
    cache.remember_token("scope", AccessToken("old", soon))
    credential = FakeCredential(value="new")
    caching = cli.CachingCredential(cache, credential)
    assert caching.get_token("scope").token == "new"


def test_dry_run_writes_no_file(azure):
    """A dry run does not even touch the cache."""
    assert cli.main(["my-kv", "db", "--dry-run"]) == 0
    assert cli.main(["my-kv", "--set", "db", "--dry-run"]) == 0
    azure.readouterr()
    assert not state.state_file().exists()
    assert not state.tokens_file().exists()


def test_empty_value_makes_no_call(azure, monkeypatch):
    """Giving up the value must not cost a round trip."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin(""))
    assert cli.main(["my-kv", "--set", "db"]) == 2
    azure.readouterr()
    assert FakeSecretClient.calls == []
    assert FakeKeyVaultManagementClient.subscriptions == []


def test_waiting_message_on_a_terminal(monkeypatch):
    """The message is written, then erased, on a terminal."""
    stderr = FakeStderr(tty=True)
    monkeypatch.setattr(cli.sys, "stderr", stderr)
    with cli.waiting("contacting Azure"):
        pass
    assert stderr.written == ["azpass: contacting Azure", "\r\033[K"]


def test_waiting_message_erased_on_error(monkeypatch):
    """The message does not stay on the screen when the call fails."""
    stderr = FakeStderr(tty=True)
    monkeypatch.setattr(cli.sys, "stderr", stderr)
    with pytest.raises(AssertionError), cli.waiting("contacting Azure"):
        raise AssertionError
    assert stderr.written[-1] == "\r\033[K"


def test_waiting_silent_on_a_pipe(monkeypatch):
    """Nothing is written when the standard error is not a terminal."""
    stderr = FakeStderr(tty=False)
    monkeypatch.setattr(cli.sys, "stderr", stderr)
    with cli.waiting("contacting Azure"):
        pass
    assert stderr.written == []


def test_library_logging_is_silenced(azure):
    """The libraries do not print the error that the command line prints itself."""
    logging.getLogger("azure").setLevel(logging.NOTSET)
    assert cli.main(["my-kv", "db"]) == 0
    assert logging.getLogger("azure").getEffectiveLevel() == logging.CRITICAL
