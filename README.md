# Database Management

It contain scripts to provision database roles and save them into Vault.

## Supported Databases

- [x] Postgres
- [x] MySQL
- [ ] MongoDB

## Configuration

The configuration file is in csv format. The sample configuration is available at [./data/config-sample.csv](./data/config-sample.csv)

| configuration     | required | description |
|-------------------|----------|-------------|
| action            | yes      | **upsert** will replace the role. **create** checks if the user role exists in vault before creating  |
| vault_addr        | yes      | the URL of the Vault Server, e.g.: http://127.0.0.1:8200  |
| vault_role_id     | no       | the role id to use with Vault app role auth method, when this configuration is empty the secret id will be used as the vault token value |
| vault_secret_id   | yes      | the secret id of the Vault app role auth method, it could be also the vault token |
| vault_path_prefix | yes      | the prefix to use to store the provisioned roles |
| security_group_id | no       | this configuration is not implemented |
| hoop_agent_ip     | no       | this configuration is not implemented |
| db_type           | yes      | the type of the database engine (postgres, mysql or mongodb). |
| db_host           | yes      | the host of the database instance |
| db_port           | yes      | the port of the database instance |
| db_admin_user     | yes      | the admin user with super privileges to provision user profiles |
| db_admin_password | yes      | the admin password |
| db_identifier     | no      | this configuration is not implemented |
| business_unit     | no      | this configuration is not implemented |
| owner_email       | no      | this configuration is not implemented |
| cto_email         | no | this configuration is not implemented |

### Vault

The `vault_addr`, `vault_role_id` and `vault_secret_id` attributes are used only in the first entry to configure Vault.
The onwards entries could be left as empty.

Roles will be provisioned using the `vault_path_prefix` in the following format: `dbmng_hoop_{role}`.

- `{dbname}` is the database name discovered for each database engine
- `{role}` is the name of the role (`ro`, `rw`, `admin`)

The path of a provisioned user will be available in the following format in a Key Value version 2:

- `{mount_path}/data/{db_type}/{db_host}/{user_role}`

Example: `dbsecrets/data/postgres/127.0.0.1/dbmng_mydbname_ro`

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
| `dbmng_hoop_ro`    | Not Implemented |
| `dbmng_hoop_rw`    | Not Implemented |
| `dbmng_hoop_admin` | Not Implemented |

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
```

## Running with Hoop

This script requires nodejs version 20+ and the following dependencies installed locally:

- csv-parse: `5.5.6`
- node-vault: `0.10.2`
- pg: `8.13.0`
- mysql2: `3.11.3`

To extend the Hoop Agent image with those dependencies, follow the steps below:

1. Create a Dockerfile and install the dependencies via `npm`

```Dockerfile
FROM hoophq/hoopdev:1.26.1

RUN npm install --global \
    csv-parse@5.5.6 \
    node-vault@0.10.2 \
    pg@8.13.0 \
    mysql2@3.11.3

RUN curl -sL https://raw.githubusercontent.com/hoophq/dbmanagement/refs/heads/main/main.js > /app/dbmanagement.js
```

2. Build and push your image to your registry

```sh
docker build -t myorg/hoopagent .
docker push myorg/hoopagent
```

3. Run your agent in your infra-structure

```sh
docker run --rm -it -e HOOP_KEY=<your-agent-key> myorg/hoopagent
```

4. Configure a connection

Create a connection in the webapp with the following attributes

- Type: `Shell`
- Command: `node /app/dbmanagement.js`
- Environment Variables: `NODE_PATH=/usr/local/lib/node_modules/`

5. Configure the csv file

Copy the file [./data/config-sample.csv](./data/config-sample.csv) and replace with your current environment configuration:

- Add Vault Server
- Add Vault Token (or role id and secret id)
- Add Prefix of the Key Value Store V2 ( e.g.: `{mount_path}/data` )
- Add the database information (type, host, user, etc)

6. Execute it

Paste the contents in the Webapp console and execute it.
