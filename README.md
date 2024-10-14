# Database Management

It contain scripts to provision database roles and save them into Vault.

## Development

1. Start Vault Server

```sh
VAULT_DEV_ROOT_TOKEN_ID=devtoken vault server -dev -dev-listen-address=0.0.0.0:8200
```

2. Deploy a Local Postgres Server

TODO

3. Install dependencies and run

```sh
npm install
npm run dev
```

### Running as Script

```sh
# file
node main.js ./data/config.csv
# from stdin
node main.js <<< $(cat ./data/config.csv)
```

## Supported Databases

- [x] Postgres
- [ ] MySQL
- [ ] MongoDB
