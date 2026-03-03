# OLDAP Media Server Deployment (Ansible)

This deploys the OLDAP media stack to:
- Host: `dhlab-iii.dhlab.unibas.ch`
- Domain: `media.oldap.org`
- Data root on VM: `/data/media`
- Compose root on VM: `/opt/oldap-mediaserver/compose`

## What gets deployed
- `lrosenth/oldap-mediahelper`
- `lrosenth/oldap-imageserver`
- `caddy:2.8`

Caddy exposes ports `80` and `443` and requests Let’s Encrypt certs for `media.oldap.org`.

## Files
- `inventory.ini`: target host and SSH user
- `group_vars/all.yml`: default deployment values
- `deploy-media.yml`: full deploy playbook
- `templates/`: rendered compose/env/Caddy files

## Prerequisites
- VPN connection to the university network is active
- SSH key-based login works to `dhlab-iii.dhlab.unibas.ch`
- Control machine has Ansible installed
- Required Ansible collections:

```bash
ansible-galaxy collection install community.docker community.general
```

## Deploy

```bash
cd ansible
ansible-playbook -i inventory.ini deploy-media.yml -K
```

`-K` prompts for the remote sudo password.

## Optional flags
- Force image refresh:

```bash
ansible-playbook -i inventory.ini deploy-media.yml -K -e force_pull=true
```

- Stop/remove stack (rollback):

```bash
ansible-playbook -i inventory.ini deploy-media.yml -K -e rollback=true
```

## Secrets
`group_vars/all.yml` currently contains `oldap_jwt_secret` for convenience. Move secrets to Ansible Vault before broader/shared usage.
