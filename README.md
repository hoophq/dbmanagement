# Database Management

It contain scripts to provision database roles and save them into Vault.

## Supported Databases

- [x] Postgres
- [x] MySQL
- [x] MongoDB Atlas

## Configuration

The configuration file is in csv format. The sample configuration is available at [./data/config-sample.csv](./data/config-sample.csv)

| configuration     | required | description |
|-------------------|----------|-------------|
| action            | yes      | **upsert** will replace the role. **create** checks if the user role exists in vault before creating  |
| vault_path_prefix | yes      | the prefix to use to store the provisioned roles |
| security_group_id | no       | this configuration is not implemented |
| hoop_agent_ip     | no       | this configuration is not implemented |
| db_type           | yes      | the type of the database engine (postgres, mysql or mongodb). |
| db_host           | yes      | the host of the database instance |
| db_port           | yes*     | the port of the database instance |
| db_admin_user     | yes*     | the admin user with super privileges to provision user profiles |
| db_admin_password | yes*     | the admin password |
| atlas_group_id    | yes*     | the Atlas project in which the users will be provisioned |
| db_identifier     | no       | this configuration is not implemented |
| business_unit     | no       | this configuration is not implemented |
| owner_email       | no       | this configuration is not implemented |
| cto_email         | no       | this configuration is not implemented |

### Environment Variables

| env              | description |
|------------------|-------------|
| CSV_FILE         | the path of csv file |
| VAULT_ADDR       | the URL of the Vault Server, e.g.: http://127.0.0.1:8200  |
| VAULT_ROLE_ID    | the role id to use with Vault app role auth method, when this configuration is empty the secret id will be used as the vault token value |
| VAULT_SECRET_ID  | the secret id of the Vault app role auth method, it could be also the vault token |
| VAULT_TOKEN      | the token to authenticate on Vault in case `VAULT_SECRET_ID` is not set |
| ATLAS_USER       | the Atlas Api key user id. Only used when it's a `mongodb-atlas` db type |
| ATLAS_USER_KEY   | the Atlas Api Secret Key. Only used when it's a `mongodb-atlas` db type |

The `VAULT_ADDR` and `VAULT_SECRET_ID` or `VAULT_TOKEN` are required attributes to connect on Vault.
To use app role authentication make sure to expose `VAULT_ROLE_ID` and `VAULT_SECRET_ID`.

> The secret id of the Vault app role auth method, it could be also the vault token

The Atlas configuration is required when provisioning users to a Mongo Atlas.
Follow this [guide](https://www.mongodb.com/docs/atlas/configure-api-access/) to obtain credentials to provision roles via Atlas API.

---

Roles will be provisioned using the `vault_path_prefix` csv configuration in the following format: `dbmng_hoop_{role}`.

- `{dbname}` is the database name discovered for each database engine
- `{role}` is the name of the role (`ro`, `rw`, `admin`)

The path of a provisioned user will be available in the following format in a Key Value version 2:

- `{mount_path}/data/{db_type}/{db_host}/{user_role}`

Example: `dbsecrets/data/postgres/127.0.0.1/dbmng_hoop_ro`

### Provisioned Roles

- **Postgres**

| role                   | privileges |
|------------------------|------------|
| `dbmng_hoop_ro`        | `SELECT`, `USAGE` on schema `public` and `LOGIN` |
| `dbmng_hoop_rw`        | `SELECT`, `INSERT`, `UPDATE`, `DELETE` |
| `dbmng_hoop_admin`     | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES` |

- **MySQL**

| role                   | privileges |
|------------------------|------------|
| `dbmng_hoop_ro`        | `SELECT` |
| `dbmng_hoop_rw`        | `SELECT`, `INSERT`, `UPDATE`, `DELETE` |
| `dbmng_hoop_admin`     | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER` |

- **MongoDB**

| role                   | privileges |
|------------------------|------------|
| `dbmng_hoop_ro`    | `readAnyDatabase` |
| `dbmng_hoop_rw`    | `readWriteAnyDatabase` |
| `dbmng_hoop_admin` | `readWriteAnyDatabase`, `userAdminAnyDatabase` |

## Development

1. Start Vault Server

```sh
VAULT_DEV_ROOT_TOKEN_ID=devtoken vault server -dev -dev-listen-address=0.0.0.0:8200
```

2. Deploy a Local Postgres / MySQL Server

- TODO

3. Copy sample configuration csv

```sh
cp ./data/config-sample.csv ./data/config.csv
```

4. Install dependencies and run

```sh
npm install
npm run dev
```

## Running as a script

Make sure to be able to reach via network the following services:

- Vault Server
- Database (MySQL, Postgres and MongoDB)

```sh
# file
node main.js ./data/config.csv
# from stdin
node main.js <<< $(cat ./data/config.csv)
# from env
CSV_FILE=./data/config.csv node main.js
```

## Running as a Hoop Runbook

This script requires nodejs version 20+ and the following dependencies installed locally:

- csv-parse: `5.5.6`
- node-vault: `0.10.2`
- pg: `8.13.0`
- mysql2: `3.11.3`
- urllib: `4.4.0`

1. Create a Dockerfile and install the dependencies via `npm`

```Dockerfile
FROM hoophq/hoopdev:1.27.4

RUN npm install --global \
    csv-parse@5.5.6 \
    node-vault@0.10.2 \
    pg@8.13.0 \
    mysql2@3.11.3 \
    urllib@4.4.0
```

2. Build and push your image to your registry

```sh
docker build -t myorg/hoopagent .
docker push myorg/hoopagent
```

3. Configure a [Runbook](https://hoop.dev/docs/learn/runbooks)

Create the file `dbmanagement.runbook.js` in your runbook repository.

4. Configure a connection

Create a connection in the Webapp with the following attributes

- Type: `Shell`
- Command: `node`
- Environment Variables: `NODE_PATH=/usr/local/lib/node_modules/`

Via cli:

```sh
hoop admin create conn node -e NODE_PATH=/usr/local/lib/node_modules/ -a '<your-agent>' -- node
```

5. Configure the csv file

Copy the file [./data/config-sample.csv](./data/config-sample.csv) and replace with your current environment configuration:

- Add Vault Server
- Add Vault Token (or role id and secret id)
- Add Prefix of the Key Value Store V2 ( e.g.: `{mount_path}/data` )
- Add the database information (type, host, user, etc)

6. Execute it via API

- Create the file `runbook-request.json` with the following content:

```json
{
  "file_name": "dbmanagement.runbook.js",
  "client_args": [],
  "env_vars": {
    "filesystem:CSV_FILE": "<base64-csv-file>",
    "envvar:VAULT_ADDR": "<base64-vault-addr>",
    "envvar:VAULT_TOKEN": "<base64-vault-token>"
  }
}
```

- Obtain an api key or a valid token
- Execute it via `curl`

```sh
export HOOP_TOKEN=
export API_URL=
curl $API_URL/api/plugins/runbooks/connections/node/exec \
 -d@runbook-request.json \
  -H "content-type: application/json" \
  -H "Authorization: Bearer $HOOP_TOKEN"
```
