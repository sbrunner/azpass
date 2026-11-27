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
azpass --search 'db*'                  # Search the secret names of all the vaults
azpass my-vault --search '*password*'  # Search the secret names of one vault
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
| `--search`       | Search the secret names with a glob                      |
| `--dry-run`      | Print the equivalent `az` command, without calling Azure |
| `--subscription` | The subscription to search into                          |
| `--vault-url`    | The URL of the key vault, for the sovereign clouds       |
| `--no-cache`     | Ignore and do not update what was remembered of Azure    |

The subscription is taken from `--subscription`, then from the
`AZURE_SUBSCRIPTION_ID` environment variable, then from the last one used, then
from the only accessible subscription. When several subscriptions are accessible
and none was ever used, the tool fails and lists them.

The key vaults are listed within a single subscription, like
`az keyvault list` does. The deletion of a secret is a soft delete, purge the
vault to remove it for good.

### Search

`--search` prints the names of the secrets matching a glob pattern, each one
prefixed by the key vault holding it:

```console
$ azpass --search '*db*'
my-vault	db
other-vault	read-only-db
```

The search runs over all the key vaults of the subscription, or over the single
one given as argument. Only the names are matched: the values are never read,
Azure does not return them for the list operation. Nothing is printed when no
secret matches, and the command still succeeds, which makes it easy to use in a
script.

### Cache

Asking Azure which subscriptions are accessible, and where a key vault lives,
costs one or two round trips. The tool therefore remembers:

- the last subscription used, and the URL of the key vaults already resolved, in
  `$XDG_CONFIG_HOME/azpass/state.json`, which holds no secret at all;
- the bearer tokens, in `$XDG_CACHE_HOME/azpass/tokens.json`.

Both files are created with the permissions `0600`, for the owner only. The
tokens are written in clear text and expire on their own, generally within an
hour: do not use this cache on a machine you do not own, `--no-cache` disables
it for one command and removing the two files resets it completely.

When Azure refuses a request because of a stale URL or token, with a status `401`,
`403` or `404`, the remembered answers are dropped and the command is tried once
again against Azure.

While a command is running, `azpass: contacting Azure` is shown on the terminal
and erased afterwards. Nothing is written when the standard error is a pipe, and
the message of a value prompt never reaches the standard output.

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

Nothing is sent to Azure during a dry run, no credential is even required, so it
works without being logged in, and no cache file is read or written. As the
subscription is not resolved, it is replaced by the `<subscription>` placeholder
in the listed key vaults command unless `--subscription` or
`AZURE_SUBSCRIPTION_ID` gives it:

```bash
$ azpass --dry-run
az keyvault list \
  --query '[].{name:name,rg:resourceGroup,url:properties.vaultUri}' \
  --output tsv --subscription '<subscription>'
```

The value of a secret is never printed by a dry run, it is replaced by
`<hidden>`.

A search over all the key vaults has no single `az` command equivalent, and
JMESPath knows no glob, so the dry run prints the shell loop, the glob being
applied by `azpass` itself:

```bash
$ azpass --search 'db*' --dry-run
for kv in $(az keyvault list --query '[].name' --output tsv --subscription '<subscription>'); do az keyvault secret list --vault-name "$kv" --query '[].name' --output tsv; done
```

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
