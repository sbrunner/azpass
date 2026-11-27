# Copyright (c) 2026, Stéphane Brunner

"""
Command line interface to Azure Key Vault.
"""

import argparse
import getpass
import json
import os
import shlex
import sys
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any, Final, Literal, TypedDict

from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import (
    DeletedSecret,
    KeyVaultSecret,
    SecretClient,
    SecretProperties,
)
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.models import Vault
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.resource.subscriptions.models import Subscription

Operation = Literal["vaults", "secrets", "get", "set", "rm"]

DEFAULT_DNS_SUFFIX: Final = "vault.azure.net"
SUBSCRIPTION_ENV_VAR: Final = "AZURE_SUBSCRIPTION_ID"
SUBSCRIPTION_PLACEHOLDER: Final = "<subscription>"
VALUE_PLACEHOLDER: Final = "<hidden>"

VAULTS_QUERY: Final = "[].{name:name,rg:resourceGroup,url:properties.vaultUri}"
SECRETS_QUERY: Final = "[].name"
VALUE_QUERY: Final = "value"
ID_QUERY: Final = "id"


class SecretAttributes(TypedDict):
    """The JSON attributes of a secret, as printed by the ``az`` CLI."""

    enabled: bool | None
    created: int | None
    updated: int | None
    expires: int | None
    recoveryLevel: str | None
    recoverableDays: int | None
    managed: bool | None


class SecretItem(TypedDict):
    """A secret entry of a ``az keyvault secret list`` JSON document."""

    id: str | None
    attributes: SecretAttributes
    tags: dict[str, str] | None


class SecretValue(SecretItem):
    """A secret entry of a ``az keyvault secret show`` JSON document."""

    value: str | None


class DeletedItem(SecretItem):
    """A secret entry of a ``az keyvault secret delete`` JSON document."""

    recoveryId: str | None
    deletedDate: int | None
    scheduledPurgeDate: int | None


class Plan(TypedDict):
    """What the user asked for, enough to print the ``az`` command without Azure."""

    operation: Operation
    vault: str | None
    key: str | None
    subscription: str | None
    vault_url: str | None
    json_output: bool


Handler = Callable[["Plan", DefaultAzureCredential], int]
"""A function doing one of the operations of the command line."""


class AzpassError(Exception):
    """An error that is a wrong use of the command line, printed without traceback."""


class NoSubscriptionError(AzpassError):
    """No subscription is accessible with the credential."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__("no accessible subscription, use --subscription")


class ManySubscriptionsError(AzpassError):
    """The subscription has to be chosen between many accessible subscriptions."""

    def __init__(self, subscriptions: Sequence[Subscription]) -> None:
        """
        Initialize.

        :param subscriptions: The accessible subscriptions.
        """
        super().__init__(
            "more than one accessible subscription, use --subscription with one of: "
            + ", ".join(
                f"{subscription.subscription_id} ({subscription.display_name})"
                for subscription in subscriptions
            )
        )


class NoValueError(AzpassError):
    """No value was given for the secret."""

    def __init__(self, source: str) -> None:
        """
        Initialize.

        :param source: Where the value was read from.
        """
        super().__init__(f"no value on {source}")


def _epoch(moment: datetime | None) -> int | None:
    """
    Convert a timestamp to the integer used by the ``az`` CLI.

    :param moment: The date to convert, ``None`` when the property is unset.
    :return: The number of seconds since the epoch, ``None`` if not set.
    """
    if moment is None:
        return None
    return int(moment.timestamp())


def _attributes(properties: SecretProperties) -> SecretAttributes:
    """
    Build the JSON attributes of a secret.

    The SDK returns the dates as ``datetime`` and the names in snake case, while
    the ``az`` CLI prints the REST names with epoch timestamps.

    :param properties: The properties of the secret, as returned by the SDK.
    :return: The attributes, ready to be serialized.
    """
    return {
        "enabled": properties.enabled,
        "created": _epoch(properties.created_on),
        "updated": _epoch(properties.updated_on),
        "expires": _epoch(properties.expires_on),
        "recoveryLevel": properties.recovery_level,
        "recoverableDays": properties.recoverable_days,
        "managed": properties.managed,
    }


def _listed_item(properties: SecretProperties) -> SecretItem:
    """
    Build the JSON representation of a secret of the list operation.

    The list operation never returns the value, so the key has to be absent from
    the document, not null, like in the ``az`` CLI output.

    :param properties: The properties of the secret, as returned by the SDK.
    :return: A dictionary shaped like the ``az`` CLI output.
    """
    return {
        "id": properties.id,
        "attributes": _attributes(properties),
        "tags": properties.tags,
    }


def _secret_item(secret: KeyVaultSecret) -> SecretValue:
    """
    Build the JSON representation of a secret with its value.

    :param secret: The secret, as returned by the SDK.
    :return: A dictionary shaped like the ``az`` CLI output.
    """
    return {
        "id": secret.id,
        "attributes": _attributes(secret.properties),
        "tags": secret.properties.tags,
        "value": secret.value,
    }


def _deleted_item(secret: DeletedSecret) -> DeletedItem:
    """
    Build the JSON representation of a deleted secret.

    :param secret: The deleted secret, as returned by the SDK.
    :return: A dictionary shaped like the ``az`` CLI output.
    """
    return {
        "id": secret.id,
        "attributes": _attributes(secret.properties),
        "tags": secret.properties.tags,
        "recoveryId": secret.recovery_id,
        "deletedDate": _epoch(secret.deleted_date),
        "scheduledPurgeDate": _epoch(secret.scheduled_purge_date),
    }


def _resource_group(vault: Vault) -> str | None:
    """
    Find the resource group of a key vault.

    The ARM answer does not contain the resource group of a resource, the ``az``
    CLI extracts it from the identifier, and so do we.

    :param vault: The vault, as returned by the SDK.
    :return: The name of the resource group, ``None`` when unknown.
    """
    elements = str(vault.id or "").split("/")
    if "resourceGroups" not in elements:
        return None
    index = elements.index("resourceGroups")
    if index + 1 >= len(elements):
        return None
    return elements[index + 1]


def _vault_item(vault: Vault) -> dict[str, Any]:
    """
    Build the JSON representation of a key vault.

    The management models are the REST models, so ``as_dict`` gives the keys of the
    ARM answer, ``vaultUri`` included; the resource group and the SKU are added at
    the top level, like the ``az`` CLI does.

    :param vault: The vault, as returned by the SDK.
    :return: A dictionary shaped like the ``az`` CLI output.
    """
    item = vault.as_dict()
    properties: dict[str, Any] = item.get("properties") or {}
    item["sku"] = properties.get("sku")
    item["resourceGroup"] = _resource_group(vault)
    return item


AZ_SUBCOMMANDS: Final[dict[Operation, str]] = {
    "secrets": "list",
    "get": "show",
    "set": "set",
    "rm": "delete",
}
"""The ``az keyvault secret`` subcommand of every operation."""

AZ_QUERIES: Final[dict[Operation, str]] = {
    "secrets": SECRETS_QUERY,
    "get": VALUE_QUERY,
    # Only the identifier of the new version is printed, the value was hidden when
    # it was typed and is not printed back.
    "set": ID_QUERY,
    "rm": ID_QUERY,
}
"""The JMESPath query of the human readable output of every operation."""


def _printing(plan: Plan, query: str) -> list[str]:
    """
    Build the output options, the query being dropped for the JSON output.

    :param plan: What the user asked for.
    :param query: The JMESPath query of the human readable output.
    :return: The options to append to the command.
    """
    if plan["json_output"]:
        return ["--output", "json"]
    return ["--query", query, "--output", "tsv"]


def _secret_arguments(plan: Plan) -> list[str]:
    """
    Build the arguments of the ``az keyvault secret`` command.

    :param plan: What the user asked for.
    :return: The arguments of the command.
    """
    arguments = ["--vault-name", str(plan["vault"])]
    if plan["operation"] != "secrets":
        arguments.extend(["--name", str(plan["key"])])
    if plan["operation"] == "set":
        # The value is never passed on the command line, it comes from the terminal
        # prompt or from a pipe, and it is never printed.
        arguments.extend(["--value", VALUE_PLACEHOLDER])
    return arguments


def build_az_command(plan: Plan) -> list[str]:
    """
    Build the ``az`` CLI command that gives the same result.

    :param plan: What the user asked for.
    :return: The command, as a list of arguments.
    """
    operation = plan["operation"]
    subscription = plan["subscription"]
    if operation == "vaults":
        # The subscription of the az CLI is the current one, azpass prints a
        # placeholder instead of guessing the one it is going to choose.
        return [
            "az",
            "keyvault",
            "list",
            *_printing(plan, VAULTS_QUERY),
            "--subscription",
            subscription or SUBSCRIPTION_PLACEHOLDER,
        ]
    return [
        "az",
        *([] if subscription is None else ["--subscription", subscription]),
        "keyvault",
        "secret",
        AZ_SUBCOMMANDS[operation],
        *_secret_arguments(plan),
        *_printing(plan, AZ_QUERIES[operation]),
    ]


def build_parser() -> argparse.ArgumentParser:
    """
    Build the argument parser.

    :return: The configured parser.
    """
    parser = argparse.ArgumentParser(
        prog="azpass",
        description="Manage the secrets of the Azure Key Vaults.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  azpass                                   List the key vaults
  azpass my-vault                          List the secrets of a key vault
  azpass my-vault my-secret                Print the value of a secret
  azpass my-vault --set my-secret          Set a secret, the value being asked
  echo hunter2 | azpass my-vault --set my-secret
                                           Set a secret read from a pipe
  azpass my-vault --rm my-secret           Delete a secret

The value of a secret is never given on the command line, it is asked without echo
or read from the standard input. Setting and deleting print the identifier of the
secret, not its value. The deletion is a soft delete, purge the vault to remove the
secret for good.
""",
    )
    parser.add_argument("vault", metavar="KEYVAULT", nargs="?", help="the key vault")
    parser.add_argument("key", metavar="KEY", nargs="?", help="the name of the secret")
    parser.add_argument(
        "--set",
        dest="set_key",
        metavar="KEY",
        help="set a secret, its value being asked or read from the standard input",
    )
    parser.add_argument(
        "--rm",
        dest="rm_key",
        metavar="KEY",
        help="delete a secret (soft delete)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="print the full JSON, like the az CLI does",
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="print the equivalent az command, without calling Azure",
    )
    parser.add_argument(
        "--subscription",
        help=f"the Azure subscription, default to the ${SUBSCRIPTION_ENV_VAR}"
        " environment variable, then to the only accessible subscription",
    )
    parser.add_argument(
        "--vault-url",
        dest="vault_url",
        help=f"the URL of the key vault, default to https://<KEYVAULT>.{DEFAULT_DNS_SUFFIX}/",
    )
    return parser


def make_plan(args: argparse.Namespace) -> Plan:
    """
    Validate the arguments and build the plan.

    :param args: The parsed arguments.
    :return: What the user asked for.
    """
    parser = build_parser()
    key = args.key
    if args.set_key is not None or args.rm_key is not None:
        if args.set_key is not None and args.rm_key is not None:
            parser.error("--set and --rm are exclusive")
        if args.key is not None:
            parser.error("the KEY argument and --set/--rm are exclusive")
        if args.vault is None:
            parser.error("--set and --rm require the KEYVAULT argument")
        if args.set_key is not None:
            key = args.set_key
            operation: Operation = "set"
        else:
            key = args.rm_key
            operation = "rm"
    elif args.vault is None:
        operation = "vaults"
    elif args.key is None:
        operation = "secrets"
    else:
        operation = "get"
    return {
        "operation": operation,
        "vault": args.vault,
        "key": key,
        "subscription": args.subscription or os.environ.get(SUBSCRIPTION_ENV_VAR),
        "vault_url": args.vault_url,
        "json_output": bool(args.json_output),
    }


def read_value(vault: str, key: str) -> str:
    """
    Read the value of the secret.

    The value is never passed as an argument, it would be visible in the process
    list and in the shell history. On a terminal it is asked without echo and the
    end of line validates it, a value spanning many lines has then to be piped. On
    a pipe the whole standard input is read, one trailing end of line being dropped.

    :param vault: The name of the key vault, shown in the prompt.
    :param key: The name of the secret, shown in the prompt.
    :return: The value of the secret.
    """
    if sys.stdin.isatty():
        # The prompt is written on the standard error, the standard output is kept
        # for the result of the command.
        prompt = f"azpass: value of the secret '{key}' in '{vault}': "
        try:
            value = getpass.getpass(prompt, sys.stderr)
        except EOFError:
            # Ctrl-D at the prompt is an end of file, an empty value like the one
            # given by an end of line.
            value = ""
        source = "the terminal"
    else:
        value = sys.stdin.read().removesuffix("\n")
        source = "the standard input"
    if value == "":
        raise NoValueError(source)
    return value


def resolve_subscription(credential: DefaultAzureCredential, explicit: str | None) -> str:
    """
    Find the subscription to search the key vaults into.

    :param credential: The Azure credential.
    :param explicit: The subscription given on the command line, if any.
    :return: The identifier of the subscription.
    """
    if explicit is not None:
        return explicit
    subscriptions = [
        subscription
        for subscription in SubscriptionClient(credential).subscriptions.list()
        # A disabled subscription cannot hold a key vault we can use.
        if subscription.state in (None, "Enabled")
    ]
    if len(subscriptions) == 1:
        subscription_id = subscriptions[0].subscription_id
        if subscription_id is not None:
            return subscription_id
    if not subscriptions:
        raise NoSubscriptionError
    raise ManySubscriptionsError(subscriptions)


def resolve_vault_url(
    credential: DefaultAzureCredential,
    vault: str,
    subscription: str | None,
    explicit: str | None,
) -> str:
    """
    Find the URL of the key vault.

    :param credential: The Azure credential.
    :param vault: The name of the key vault.
    :param subscription: The subscription to search into, if already known.
    :param explicit: The URL given on the command line, if any.
    :return: The URL of the key vault.
    """
    if explicit is not None:
        return explicit
    default_url = _default_url(vault)
    if subscription is None:
        return default_url
    # The lookup only gives a better default on sovereign clouds, and we are not
    # always allowed to read the management plane, the classical URL is then used.
    try:
        vaults = KeyVaultManagementClient(credential, subscription).vaults.list_by_subscription()
    except AzureError:
        return default_url
    for candidate in vaults:
        if candidate.name == vault:
            return _vault_url(candidate)
    return default_url


def _default_url(vault: str) -> str:
    """
    Build the URL of a key vault of the public cloud.

    :param vault: The name of the key vault.
    :return: The URL of the key vault.
    """
    return f"https://{vault}.{DEFAULT_DNS_SUFFIX}/"


def _vault_url(vault: Vault) -> str:
    """
    Build the URL of a key vault returned by the management plane.

    :param vault: The vault, as returned by the SDK.
    :return: The URL declared by Azure, the public cloud one when it is silent.
    """
    properties = vault.properties
    if properties is None or properties.vault_uri is None:
        return _default_url(str(vault.name))
    return str(properties.vault_uri)


def print_json(payload: Any) -> None:
    """
    Print a JSON document.

    :param payload: The document to print, any JSON serializable value.
    """
    print(json.dumps(payload, indent=2, sort_keys=True))


def list_vaults(plan: Plan, credential: DefaultAzureCredential) -> int:
    """
    List the key vaults of the subscription.

    :param plan: What the user asked for.
    :param credential: The Azure credential.
    :return: The exit code.
    """
    subscription = resolve_subscription(credential, plan["subscription"])
    client = KeyVaultManagementClient(credential, subscription)
    vaults = list(client.vaults.list_by_subscription())
    if plan["json_output"]:
        print_json([_vault_item(vault) for vault in vaults])
        return 0
    for vault in vaults:
        print("\t".join((str(vault.name), str(_resource_group(vault)), _vault_url(vault))))
    return 0


def _secret_client(plan: Plan, credential: DefaultAzureCredential) -> SecretClient:
    """
    Build the data plane client of the key vault.

    :param plan: What the user asked for.
    :param credential: The Azure credential.
    :return: The client.
    """
    vault_url = resolve_vault_url(credential, str(plan["vault"]), plan["subscription"], plan["vault_url"])
    return SecretClient(vault_url, credential)


def list_secrets(plan: Plan, credential: DefaultAzureCredential) -> int:
    """
    List the secrets of a key vault.

    :param plan: What the user asked for.
    :param credential: The Azure credential.
    :return: The exit code.
    """
    client = _secret_client(plan, credential)
    properties_list = list(client.list_properties_of_secrets())
    if plan["json_output"]:
        print_json([_listed_item(properties) for properties in properties_list])
        return 0
    for properties in properties_list:
        print(str(properties.name))
    return 0


def get_secret(plan: Plan, credential: DefaultAzureCredential) -> int:
    """
    Print the value of a secret.

    :param plan: What the user asked for.
    :param credential: The Azure credential.
    :return: The exit code.
    """
    secret = _secret_client(plan, credential).get_secret(str(plan["key"]))
    if plan["json_output"]:
        print_json(_secret_item(secret))
    else:
        print(str(secret.value))
    return 0


def set_secret(plan: Plan, credential: DefaultAzureCredential) -> int:
    """
    Create a new version of a secret.

    :param plan: What the user asked for.
    :param credential: The Azure credential.
    :return: The exit code.
    """
    client = _secret_client(plan, credential)
    secret = client.set_secret(str(plan["key"]), read_value(str(plan["vault"]), str(plan["key"])))
    if plan["json_output"]:
        print_json(_secret_item(secret))
    else:
        # The identifier of the new version, the value is not printed back.
        print(str(secret.id))
    return 0


def delete_secret(plan: Plan, credential: DefaultAzureCredential) -> int:
    """
    Delete a secret, the soft delete keeping it recoverable.

    :param plan: What the user asked for.
    :param credential: The Azure credential.
    :return: The exit code.
    """
    client = _secret_client(plan, credential)
    deleted = client.begin_delete_secret(str(plan["key"])).result()
    if plan["json_output"]:
        print_json(_deleted_item(deleted))
    else:
        print(str(deleted.id))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """
    Run the command line.

    :param argv: The arguments, default to the command line.
    :return: The exit code.
    """
    args = build_parser().parse_args(argv)
    plan = make_plan(args)
    if args.dry_run:
        # Nothing is sent to Azure on a dry run, no credential and no subscription.
        print(shlex.join(build_az_command(plan)))
        return 0
    handlers: dict[Operation, Handler] = {
        "vaults": list_vaults,
        "secrets": list_secrets,
        "get": get_secret,
        "set": set_secret,
        "rm": delete_secret,
    }
    try:
        return handlers[plan["operation"]](plan, DefaultAzureCredential())
    except AzureError as exception:
        # An Azure error is a user error (no right, wrong name, no such secret), it
        # has to be reported as a message, not as a Python traceback.
        print(f"azpass: error: {exception}", file=sys.stderr)
        return 1
    except AzpassError as exception:
        # The user has to give a missing parameter, the message is enough.
        print(f"azpass: error: {exception}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        # The user interrupted the command, while typing a value or during a call, an
        # interruption is not a bug and does not deserve a Python traceback. The exit
        # code is the conventional 128 + SIGINT.
        print("azpass: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
