# azpass

Command line tool to manage the secrets of the Azure Key Vaults.

The tool uses the Azure Python SDK and the usual Azure authentication
(`az login`, service principal through the `AZURE_*` environment variables,
managed identity). Every operation has an equivalent [`az`][az-cli] command,
which `--dry-run` prints.

## Install

```bash
python3 -m pip install --user azpass
```

## Usage

```bash
azpass                                 # List the key vaults
azpass my-vault                        # List the secrets of a key vault
azpass my-vault my-secret              # Print the value of a secret
azpass my-vault --set my-secret        # Set a secret, the value being asked
azpass my-vault --rm my-secret         # Delete a secret
```

The value of a secret is never given as an argument: an argument would be visible
in the shell history and in the process list. On a terminal it is asked without
echo, and the end of line validates it:

```console
$ azpass my-vault --set my-secret
azpass: value of the secret 'my-secret' in 'my-vault': ********
https://my-vault.vault.azure.net/secrets/my-secret/89a1c00898fc...
```

It can also be piped, which is the only way to set a value spanning many lines:

```bash
echo hunter2 | azpass my-vault --set my-secret
azpass my-vault --set my-cert < my-cert.pem
```

One trailing end of line is dropped, so a value ending with a real end of line
has to be piped without it, with `printf` for example.

`--set` creates a new version of the secret, the previous ones remaining
available until the deletion of the secret. It prints the identifier of the new
version, `azpass my-vault my-secret` gives the value back.

### Options

| Option           | Description                                              |
| ---------------- | -------------------------------------------------------- |
| `--json`         | Print the full JSON document, like the `az` CLI does     |
| `--dry-run`      | Print the equivalent `az` command, without calling Azure |
| `--subscription` | The subscription to search into                          |
| `--vault-url`    | The URL of the key vault, for the sovereign clouds       |

The subscription is taken from `--subscription`, then from the
`AZURE_SUBSCRIPTION_ID` environment variable, then from the only accessible
subscription. When several subscriptions are accessible, the tool fails and
lists them.

The key vaults are listed within a single subscription, like
`az keyvault list` does. The deletion of a secret is a soft delete, purge the
vault to remove it for good.

### JSON output

The JSON documents are the ones of the `az` CLI, `--dry-run --json` gives the
command that produces them:

```bash
$ azpass my-vault my-secret --dry-run --json
az keyvault secret show --vault-name my-vault --name my-secret --output json
```

The list of the secrets never contains the values, Azure does not return them
for that operation.

### Dry run

Nothing is sent to Azure during a dry run, no credential is even required, so
it works without being logged in. As the subscription is not resolved, it is
replaced by the `<subscription>` placeholder in the listed key vaults command
unless `--subscription` or `AZURE_SUBSCRIPTION_ID` gives it:

```bash
$ azpass --dry-run
az keyvault list \
  --query '[].{name:name,rg:resourceGroup,url:properties.vaultUrl}' \
  --output tsv --subscription '<subscription>'
```

The value of a secret is never printed by a dry run, it is replaced by
`<hidden>`.

## Authentication

`DefaultAzureCredential` of the `azure-identity` package is used, so any of the
classical methods works. The simplest one is:

```bash
az login
```

The account needs the read permission on the key vaults of the subscription
(`Key Vault Reader` or `Owner`), and on the secrets the `Key Vault Secrets User`
role to read them, `Key Vault Secrets Officer` to set or delete them, unless the
vault uses the legacy access policies.

## Run tests and prospector

```bash
python3 -m pip install --user --upgrade poetry
poetry install
poetry run pytest
poetry run prospector --output=pylint azpass
```

## Create new release

```bash
git tag <version>
git push origin <version>
```

## Contributing

Install the pre-commit hooks:

```bash
pip install pre-commit
pre-commit install --allow-missing-config
```

[az-cli]: https://learn.microsoft.com/en-us/cli/azure/keyvault
