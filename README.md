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
| action            | yes      | **upsert** will replace the role. **create** check if the user role exists in Vault before creating |
| vault_path_prefix | yes      | the prefix to use to store the provisioned roles |
| security_group_id | no       | this configuration is not implemented |
| hoop_agent_ip     | no       | this configuration is not implemented |
| connection_string | yes      | the connection string of the database, accept (`mongodb-atlas://`, `postgres://` and `mysql://`). |
| atlas_group_id    | yes*     | the Atlas project in which the users will be provisioned |
| db_identifier     | no       | this configuration is not implemented |
| business_unit     | no       | this configuration is not implemented |
| owner_email       | no       | this configuration is not implemented |
| cto_email         | no       | this configuration is not implemented |

### Environment Variables

| env                   | required | description |
|---------------------- | -------- | ------------|
| CSV_FILE              | yes      | the path of csv file |
| VAULT_ADDR            | yes      | the URL of the Vault Server, e.g.: http://127.0.0.1:8200  |
| VAULT_ROLE_ID         | no       | the role id to use with Vault app role auth method, when this configuration is empty the secret id will be used as the vault token value |
| VAULT_SECRET_ID       | no       | the secret id of the Vault app role auth method, it could be also the vault token |
| VAULT_TOKEN           | no       | the token to authenticate on Vault in case `VAULT_SECRET_ID` is not set |
| ATLAS_USER            | no       | the Atlas Api key user id. Only used when it's a `mongodb-atlas` db type |
| ATLAS_USER_KEY        | no       | the Atlas Api Secret Key. Only used when it's a `mongodb-atlas` db type |
| PGSSLROOTCERT         | no       | the root CA cert for connecting via SSL for postgres instances |
| AWS_ACCESS_KEY_ID     | no       | step functions aws access key id |
| AWS_SECRET_ACCESS_KEY | no       | step functions aws secret access key |
| AWS_REGION            | no       | step functions aws region |
| SFN_ARN               | yes      | the step functions arn to execute |

The `VAULT_ADDR` and `VAULT_SECRET_ID` or `VAULT_TOKEN` are required attributes to connect on Vault.
To use app role authentication make sure to expose `VAULT_ROLE_ID` and `VAULT_SECRET_ID`.

> The secret id of the Vault app role auth method, it could be also the vault token

The Atlas configuration is required when provisioning users to a Mongo Atlas.
Follow this [guide](https://www.mongodb.com/docs/atlas/configure-api-access/) to obtain credentials to provision roles via Atlas API.

---

Roles will be provisioned using the `vault_path_prefix` csv configuration in the following format: `hoop_{role}`.

- `{role}` is the name of the role (`ro`, `rw`, `ddl`)
- `{db_hostname}` is the hostname identified in the connection string
- `{db_identifier}` is the identifier of the instance in the csv file

The path of a provisioned user will be available in the following format in a Key Value version 2:

**Postgres / MySQL**

- `{mount_path}/data/hoop_{role}_{db_hostname}`

Vault Secret

```json
{
  "HOST": "<db-host>",
  "PORT": "<db-port>",
  "USER": "<db-user>",
  "PASSWORD": "<db-password>",
  "DB": "<db-name>"
}
```

**MongoDB**

- `{mount_path}/data/hoop_{role}_{db_identifier}_{db_hostname}`

Vault Secret

```json
{
  "URI": "<connection-string>",
  "URI_RW": "<connection-string>"
}
```

Examples:

- `dbsecrets/data/hoop_rw_127.0.0.1`
- `dbsecrets/data/hoop_ro_mongodb-cluster_127.0.0.1`
- `dbsecrets/data/hoop_ddl_127.0.0.1`

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

### Step Functions

To configure the step functions, it's necessary the `SFN_ARN` environment variable.
By default it will use the default AWS credentials available in the instance.

#### Using AWS Environment Variables

Set the following variables

- AWS_REGION
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY

#### Using credentials from a managed instance

Export the following variables to your connection

- `AWS_WEB_IDENTITY_TOKEN_FILE=system.agent.envs`
- `AWS_ROLE_ARN=system.agent.envs`

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
- @aws-sdk/client-sfn: `3.687.0`

1. Create a Dockerfile and install the dependencies via `npm`

```Dockerfile
FROM hoophq/hoopdev:1.27.12

RUN npm install --global \
    csv-parse@5.5.6 \
    node-vault@0.10.2 \
    pg@8.13.0 \
    mysql2@3.11.3 \
    urllib@4.4.0 \
    @aws-sdk/client-sfn@3.687.0
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
