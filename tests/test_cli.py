# Copyright (c) 2026, Stéphane Brunner

"""Tests of the command line."""

import json
import shlex
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from azure.core.exceptions import AzureError

from azpass import cli

CREATED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
UPDATED = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
DELETED = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
VAULT_URL = "https://my-kv.vault.azure.net/"

CREATED_EPOCH = 1767323045
UPDATED_EPOCH = 1770091506
DELETED_EPOCH = 1772600767


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

    id: str = "https://my-kv.vault.azure.net/secrets/db/version"
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

    def __init__(self, value: str) -> None:
        self.value = value
        self.reads = 0

    def read(self) -> str:
        """Read the value."""
        self.reads += 1
        return self.value


@dataclass
class FakeSubscription:
    """A fake ``Subscription``."""

    subscription_id: str = "sub-1"
    display_name: str = "My subscription"
    state: str | None = "Enabled"


class FakeSecretClient:
    """A fake ``SecretClient`` recording the calls."""

    calls: list = []

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
        return FakeSecret(value=value)

    def begin_delete_secret(self, name: str) -> FakePoller:
        """Delete a secret."""
        assert name == "db"
        return FakePoller()


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
def azure(monkeypatch, capsys):
    """Patch all the Azure entry points of the command line."""
    FakeSecretClient.calls = []
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
    assert "top secret" not in azure.readouterr().out


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
    assert FakeSecretClient.calls == [(VAULT_URL, "credential")]


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
    """The value of the secret comes from the standard input."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin("hunter2\n"))
    assert cli.main(["my-kv", "--set", "db"]) == 0
    assert azure.readouterr().out == "hunter2\n"


def test_set_secret_keeps_the_inner_ends_of_line(azure, monkeypatch):
    """Only one trailing end of line is dropped."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin("a\nb\n\n"))
    assert cli.main(["my-kv", "--set", "db"]) == 0
    assert azure.readouterr().out == "a\nb\n\n"


def test_set_secret_without_value(azure, monkeypatch):
    """An empty standard input is an error."""
    monkeypatch.setattr(cli.sys, "stdin", FakeStdin(""))
    with pytest.raises(SystemExit) as exception:
        cli.main(["my-kv", "--set", "db"])
    assert exception.value.code == 2
    assert "no value on the standard input" in azure.readouterr().err


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
