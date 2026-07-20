# OLDAP Media Server Deployment (Ansible)

By default this deploys the OLDAP media stack to:
- Host: `dhlab-iii.dhlab.unibas.ch`
- Domain: `media.oldap.org`
- Data root on VM: `/data/media`
- Compose root on VM: `/opt/oldap-mediaserver/compose`

The inventory also contains a separate test target:
- Host/domain: `media.home.org`
- Caddy listens on both `http://media.home.org` and `https://media.home.org`
- HTTPS uses Caddy's internal CA because the host has no public ACME/Let's Encrypt name

## What gets deployed
- `lrosenth/oldap-mediahelper:<explicit tag from mediaserver/VERSION>`
- `lrosenth/oldap-imageserver:<explicit tag from imageserver/VERSION>`
- `caddy:2.8`

Caddy exposes ports `80` and `443`.
For the default production target it requests Let's Encrypt certs for `media.oldap.org`.
For `media.home.org` it uses Caddy's internal CA instead.

## Files
- `inventory.ini`: target host and SSH user
- `group_vars/all.yml`: default deployment values
- `host_vars/media.home.org.yml`: test-server overrides for `media.home.org`
- `deploy-media.yml`: full deploy playbook
- `templates/`: rendered compose/env/Caddy files

## Prerequisites
On the control machine, install Ansible. On macOS this can be done with Homebrew:

```bash
brew update
brew install ansible
```

Install the Ansible collections used by the playbook:

```bash
ansible-galaxy collection install community.docker community.general
```

Check the local installation:

```bash
ansible --version
ansible-playbook --version
ansible-galaxy --version
```

Notes:
- Jinja2 is normally installed as part of the Ansible installation.
- Docker does not need to be installed locally for deployment. The playbook installs Docker on the remote host.
- For production, VPN access to the university network must be active.
- For `media.home.org`, the name must resolve from the control machine. If DNS does not provide it, add it to `/etc/hosts`.

Example `/etc/hosts` entry:

```text
192.168.x.y media.home.org
```

Replace `192.168.x.y` with the actual IP address of the test server.

## Preflight Checks

Check that Ansible parses the inventory:

```bash
cd ansible
ansible-inventory -i inventory.ini --graph
```

Check that the playbook syntax is valid:

```bash
ansible-playbook -i inventory.ini deploy-media.yml --syntax-check
```

Check SSH access to the test server:

```bash
ssh rosenth@media.home.org
```

Check sudo directly on the test server:

```bash
ssh media.home.org "sudo -v"
```

Check Ansible access to the test server. Because the inventory enables `become`, use `-K` so Ansible can ask for the remote sudo password:

```bash
ansible media.home.org -i inventory.ini -m ping -K -T 60
```

To test SSH only, without sudo/become:

```bash
ansible media.home.org -i inventory.ini -m ping -e ansible_become=false
```

If SSH works but Ansible fails while waiting for privilege escalation, rerun with verbose output:

```bash
ansible media.home.org -i inventory.ini -m ping -K -T 60 -vvvv
```

The test host pins `ansible_python_interpreter: /usr/bin/python3.14` in `host_vars/media.home.org.yml`. This avoids interpreter-discovery warnings.
The `-T 60` option gives the SSH/become prompt more time to answer; this is useful if sudo or PAM responds slowly.
For `media.home.org`, `host_vars/media.home.org.yml` also sets:

```yaml
ansible_become_exe: /usr/bin/sudo.ws
ansible_become_method: sudo
ansible_become_user: root
ansible_become_flags: "-H -S"
```

This uses Ubuntu's classic sudo implementation for Ansible privilege escalation and keeps sudo password input on stdin. This is needed on Ubuntu releases where `sudo` points to `sudo-rs`, whose prompt can confuse prompt-based automation.

Check that `sudo.ws` exists on the test server:

```bash
ssh media.home.org "command -v sudo.ws && sudo.ws -V | head -1"
```

## Deploy Production

```bash
make show-versions
make deploy-production
```

Run these commands from the repository root. `make deploy-production` derives
the mediahelper and imageserver tags from their component `VERSION` files,
passes them to Ansible as `oldap_mediahelper_tag` and
`oldap_imageserver_tag`, and targets only the production group `mediaserver`,
currently `dhlab-iii.dhlab.unibas.ch`.
`-K` prompts for the remote sudo password.

## Deploy Test Server

```bash
make show-versions
make deploy-test
```

Run these commands from the repository root. This targets only the test group
`test_mediaserver`, currently `media.home.org`, and passes both derived
component tags explicitly.

The test server gets these host-specific overrides from `host_vars/media.home.org.yml`:
- `media_domain: media.home.org`
- `oldap_api_url: http://api.rosy.home.org`
- Docker container host aliases:
  - `api.rosy.home.org:192.168.1.10`
  - `app.rosy.home.org:192.168.1.10`
  - `graphdb.rosy.home.org:192.168.1.10`
- Caddy site addresses: `http://media.home.org` and `https://media.home.org`
- `caddy_tls_internal: true`
- `caddy_auto_https: disable_redirects`

The `oldap-mediahelper` and `oldap-imageserver` containers receive this as `OLDAP_API_URL=http://api.rosy.home.org` in `mediaserver.env`.
The Docker Compose file also adds the `*.rosy.home.org` names to the containers via `extra_hosts`, so they resolve inside the containers even if Docker does not inherit the host's `/etc/hosts` entries.

The important consequence is that Caddy serves both HTTP and HTTPS for `media.home.org`, but HTTPS uses Caddy's internal CA instead of Let's Encrypt. Browsers will not trust that certificate automatically unless the Caddy internal root CA is trusted on the client.

## Production Safety

The playbook defaults remain production-oriented:
- `deploy-media.yml` defaults to `target_hosts=mediaserver`
- `group_vars/all.yml` remains the shared/default configuration for `media.oldap.org`
- `media.home.org` settings live in `host_vars/media.home.org.yml`
- `oldap_mediahelper_tag` and `oldap_imageserver_tag` have no silent Ansible
  defaults and must be supplied explicitly; the repository-root Makefile
  provides both for normal deployments

Therefore, the test server is deployed only when explicitly requested with:

```bash
make deploy-test
```

## Optional flags
- Deploy or roll back to a specific imageserver image:

```bash
make deploy-production IMAGESERVER_TAG=v0.1.5
```

- Deploy or roll back to a specific mediahelper image:

```bash
make deploy-production MEDIAHELPER_TAG=v0.0.14
```

- Force image refresh:

```bash
make deploy-production ANSIBLE_ARGS='-e force_pull=true'
```

- Force image refresh on the test server:

```bash
make deploy-test ANSIBLE_ARGS='-e force_pull=true'
```

- Stop/remove stack (rollback):

```bash
make deploy-production ANSIBLE_ARGS='-e rollback=true'
```

- Stop/remove stack on the test server:

```bash
make deploy-test ANSIBLE_ARGS='-e rollback=true'
```

## Authentication secrets

The media deployment requires two independent signing keys:

- `oldap_access_jwt_secret` verifies API Bearer tokens on `/upload`.
- `oldap_media_jwt_secret` verifies `typ=media` capabilities on `/asset` and
  IIIF requests.

Both values must exactly match the corresponding `OLDAP_ACCESS_JWT_SECRET` and
`OLDAP_MEDIA_JWT_SECRET` values deployed to `oldap-api`, and each must contain
at least 32 bytes. They must not equal one another. No secret is stored in
`group_vars/all.yml` or committed to Git.

The repository-root Makefile defaults to the shared encrypted
`$HOME/ProgDev/OLDAP/auth/auth.vault.yml`, passes it as `auth_secrets_file`, and
uses `--ask-vault-pass`. Consequently, the normal commands need no additional
secret arguments:

```bash
make deploy-test
make deploy-production
```

The path and Vault arguments remain overridable when required:

```bash
make deploy-production \
  AUTH_SECRETS_FILE=/secure/path/oldap-auth.vault.yml \
  ANSIBLE_VAULT_ARGS='--vault-id production@prompt'
```

The playbook validates both keys before changing the host. It renders a shared
root-only `mediaserver.env` containing the media key and a separate root-only
`mediahelper-access.env` containing the access key. Only the Flask media-helper
container receives the access-key file; Cantaloupe receives only the media-key
environment.
