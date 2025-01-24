const vault = require("node-vault");
const csvsync = require("csv-parse/sync");
const fs = require("node:fs");
const crypto = require("node:crypto");
const util = require("node:util");
const urllib = require("urllib");
const net = require("net");
const pg = require("pg");
const mysql = require("mysql2");
const { SFNClient, StartExecutionCommand } = require("@aws-sdk/client-sfn");

const user_prefix = "hoop";
const defaultConnectTimeoutMs = 7000; // 7s
const roRole = "ro";
const rwRole = "rw";
const adminRole = "ddl";
const roleList = [roRole, rwRole, adminRole];

const baseAtlasAPIUrl = "https://cloud.mongodb.com/api/atlas/v2";
const { ATLAS_USER, ATLAS_USER_KEY } = process.env;

const postgresRoles = {
  [roRole]: (o) => {
    o.privileges = "SELECT";
    return `
DO $$
  DECLARE
    role_count int;
    db_schema_name text;
BEGIN
  -- create role or alter the password
  SELECT COUNT(*) INTO role_count FROM pg_roles WHERE rolname = '${o.user}';
  IF role_count > 0 THEN
    ALTER ROLE "${o.user}" WITH LOGIN ENCRYPTED PASSWORD '${o.password}';
  ELSE
    CREATE ROLE "${o.user}" WITH LOGIN ENCRYPTED PASSWORD '${o.password}' NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER;
  END IF;

  -- grant the privileges to the new or existing role for all schemas
  FOR db_schema_name IN
    SELECT schema_name
    FROM information_schema.schemata
    WHERE schema_name NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
  LOOP
    EXECUTE 'GRANT USAGE ON SCHEMA ' || db_schema_name || ' TO "${o.user}"';
    EXECUTE 'GRANT ${o.privileges} ON ALL TABLES IN SCHEMA ' || db_schema_name || ' TO "${o.user}"';
  END LOOP;
END$$;`;
  },
  [rwRole]: (o) => {
    o.privileges = "SELECT, INSERT, UPDATE, DELETE";
    return postgresRoles[roRole](o);
  },
  [adminRole]: (o) => {
    o.privileges =
      "SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER";
    return postgresRoles[roRole](o);
  },
};

const mysqlRoles = {
  [roRole]: (o) => `
START TRANSACTION;
DROP USER IF EXISTS '${o.user}';
CREATE USER '${o.user}'@'%' IDENTIFIED BY '${o.password}';
GRANT SELECT ON *.* TO '${o.user}'@'%';
FLUSH PRIVILEGES;
COMMIT;`,
  [rwRole]: (o) => `
START TRANSACTION;
DROP USER IF EXISTS '${o.user}';
CREATE USER '${o.user}'@'%' IDENTIFIED BY '${o.password}';
GRANT SELECT, DELETE, UPDATE, INSERT ON *.* TO '${o.user}'@'%';
FLUSH PRIVILEGES;
COMMIT;`,
  [adminRole]: (o) => `
START TRANSACTION;
DROP USER IF EXISTS '${o.user}';
CREATE USER '${o.user}'@'%' IDENTIFIED BY '${o.password}';
GRANT SELECT, DELETE, UPDATE, INSERT, ALTER, CREATE, DROP ON *.* TO '${o.user}'@'%';
FLUSH PRIVILEGES;
COMMIT;`,
};

const mongodbAtlasRoles = {
  [roRole]: (o) => {
    const identifier = o.dbIdentifier;
    if (!o.roles) {
      o.roles = [{ databaseName: "admin", roleName: "readAnyDatabase" }];
    }
    return {
      username: o.user,
      password: o.password,
      description: `Provisioned by ${user_prefix}`,
      labels: [],
      scopes: [{ name: identifier, type: 'CLUSTER' }],
      databaseName: "admin",
      groupId: o.atlasGroupID,
      roles: o.roles,
    };
  },
  [rwRole]: (o) => {
    o.roles = [{ databaseName: "admin", roleName: "readWriteAnyDatabase" }];
    return mongodbAtlasRoles[roRole](o);
  },
  [adminRole]: (o) => {
    o.roles = [
      { databaseName: "admin", roleName: "atlasAdmin" },
      { databaseName: "local", roleName: "dbAdmin" },
    ];
    return mongodbAtlasRoles[roRole](o);
  },
};

function openCsvConfig(csvFile) {
  const csvData = fs.readFileSync(csvFile);
  const dbinstances = csvsync.parse(csvData, {
    columns: true,
    skip_empty_lines: true,
    trim: true,
  });
  errors = [];
  for (const [index, csv] of dbinstances.entries()) {
    if (csv.vault_path_prefix == "") {
      errors.push(`record=${index} vault_path_prefix is required`);
    }

    if (csv.action != "create" && csv.action != "upsert") {
      errors.push("wrong action type, accept (create or upsert)");
    }

    if (!csv.db_identifier) {
      errors.push(`record=${index} missing db_identifier attribute`,);
    }
    const uri = parse_uri(csv.connection_string)
    if (
      uri.scheme != "mongodb-atlas" &&
      uri.scheme != "mysql" &&
      uri.scheme != "postgres"
    ) {
      errors.push(
        `record=${index} wrong type for connection string (scheme=${uri.scheme}), accepted: postgres://, mysql:// or mongodb-atlas://`,
      );
    }
    if (uri.scheme == "mongodb-atlas" && csv.atlas_group_id == "") {
      errors.push(`record=${index} missing atlas_group_id attribute`);
    }

    if (uri.scheme == "mysql" || uri.scheme == "postgres") {
      if (!uri.username || !uri.password) {
        errors.push(`record=${index} missing username or password in connection string`);
      }
      const hostEntry = uri.hosts[0];
      if (!hostEntry?.host || !hostEntry?.port) {
        errors.push(`record=${index} missing host or port in connection string`);
      }
    }
  }
  if (errors.length > 0) {
    throw new Error(errors.join("\n"));
  }
  return dbinstances;
}

async function httpRequest(method, uri, data) {
  const options = {
    digestAuth: `${ATLAS_USER}:${ATLAS_USER_KEY}`,
    headers: {
      Accept: "application/vnd.atlas.2023-01-01+json",
    },
    method: method,
    data: data,
    contentType: "json",
  };
  const res = await urllib.request(uri, options);
  if (res.data != null) {
    try {
      res.data = res.data.toString();
    } catch (_) {}
  }
  return res;
}

function checkLiveness(host, port) {
  host = host ? host : "";
  port = port ? port : 0;
  return new Promise((resolve, _) => {
    if (host == "" || port == 0) {
      resolve("missing host or port configuration");
      return;
    }
    const client = net.connect(port, host, () => {
      client.end();
      resolve(null);
    });
    client.on("error", (err) => {
      client.end();
      resolve(err);
    });
  });
}

async function fetchPgDatabases(connStr) {
  const dbItems = [];
  try {
    const pgClient = new pg.Client({
      ssl: process.env.PGSSLROOTCERT ? {
        ca: fs.readFileSync(process.env.PGSSLROOTCERT).toString(),
      } : false,
      host: connStr.firstHost.host,
      port: connStr.firstHost.port,
      user: connStr.username,
      password: connStr.password,
      database: "postgres",
      application_name: user_prefix,
      dialectOptions: {
        ssl: {
          require: true,
          rejectUnauthorized: false
        }
      },
      connectionTimeoutMillis: defaultConnectTimeoutMs,
    });

    // it could blow up with uncaught exception
    // https://github.com/brianc/node-postgres/issues/1927
    await pgClient.connect();
    const res = await pgClient
      .query(
        `
      SELECT datname as dbname
      FROM pg_database
      WHERE datname NOT IN ('template0', 'template1', 'rdsadmin')`,
      )
      .catch((ex) => {
        pgClient.end();
        throw ex;
      });
    await pgClient.end();

    if (res.rowCount == 0) {
      return { items: [], err: null };
    }

    for (row of res.rows) {
      dbItems.push(row.dbname);
    }
  } catch (ex) {
    return { items: [], err: ex };
  }
  return { items: dbItems, err: null };
}

async function getVaultSecret(vaultClient, path) {
  return new Promise((resolve, _) => {
    vaultClient
      .read(path)
      .then((res) => {
        // console.log(res);
        const data = res.data ? res.data : {};
        resolve({
          payload: {
            requestID: res.request_id,
            warnings: res.warnings,
            version: data.metadata.version ? data.metadata.version : -1,
            destroyed: data.metadata.destroyed,
            data: res.data,
          },
          err: null,
        });
      })
      .catch((ex) => {
        const res = ex.response ? ex.response : {};
        // TODO: add debug response here
        resolve({
          payload: {
            requestID: "",
            warnings: [],
            version: "",
            destroyed: "",
            data: {},
          },
          err: { statusCode: res.statusCode, body: res.body },
        });
      });
  });
}

async function putVaultSecret(vaultClient, path, data) {
  return new Promise((resolve, _) => {
    vaultClient
      .write(
        path,
        {
          // version 2 KV
          data: data,
        },
        { followAllRedirects: true },
      )
      .then((res) => {
        resolve({
          payload: {
            requestID: res.request_id,
            warnings: res.warnings,
            version: res.data.version,
            destroyed: res.data.destroyed,
          },
          err: null,
        });
      })
      .catch((ex) => {
        // console.log(ex.response);
        const res = ex.response ? ex.response : {};
        resolve({
          payload: { requestID: "", warnings: [], version: -1, destroyed: "" },
          err: { statusCode: res.statusCode, body: res.body },
        });
      });
  });
}

async function newVaultClient(addr, roleID, secretID) {
  const opts = {
    apiVersion: "v1",
    endpoint: addr,
    role_id: roleID ? roleID : "",
    secret_id: secretID,
    token: secretID,
  };
  let vaultClient = vault(opts);
  if (opts.role_id != "") {
    console.log("--> performing login via approle auth method");
    let res = await vaultClient.approleLogin(opts);
    let { client_token, policies, lease_duration, token_type } = res.auth;
    console.log(
      `--> got response from approle login, policies=${policies}, lease_duration=${lease_duration}, token_type=${token_type}`,
    );

    opts.token = client_token;
    vaultClient = vault(opts);
  }
  const options = { requestOptions: { timeout: defaultConnectTimeoutMs } };
  let res = await vaultClient.health(options);
  console.log(
    `--> Vault health response from address ${addr ? addr : '<empty>'}, version=${res?.version}, initialized=${res?.initialized}, sealed=${res?.sealed}`,
  );
  if (!res?.initialized) {
    throw new Error(`Vault is not initialized, check the Vault client configuration.`)
  }
  return vaultClient;
}

function parseVaultPayload(uri, roleName, username, password) {
  let { host, port } = uri.firstHost;
  const { scheme } = uri;
  switch (scheme) {
  case "mysql":
    if (!port) {
      port = '3306'
    }
    return {
      HOST: host,
      DB: 'mysql',
      PASSWORD: password,
      PORT: port,
      USER: username,
    };
  case "postgres":
    if (!port) {
      port = '5432'
    }
    return {
      HOST: host,
      DB: 'postgres',
      PASSWORD: password,
      PORT: port,
      USER: username,
    };
  case "mongodb-atlas":
    if (!port) {
      port = '27017'
    }
    if (roleName == adminRole) {
      return {
        URI: `mongodb+srv://${username}:${password}@${host}/admin?retryWrites=true&w=majority&readPreference=secondary`,
        URI_RW: `mongodb+srv://${username}:${password}@${host}/admin?readPreference=primary`,
      }
    } else if (roleName == rwRole) {
      return { URI: `mongodb+srv://${username}:${password}@${host}/admin?readPreference=primary` }
    }
    return { URI: `mongodb+srv://${username}:${password}@${host}/admin?retryWrites=true&w=majority&readPreference=secondary` }
  default:
    throw new Error(`scheme ${scheme} not supported`);
  }
}

async function provisionRoles(csv, userRoleName, roleName, password) {
  const csuri = parse_uri(csv.connection_string);
  const dbEntry = `${csuri.scheme}/${csuri.firstHost.host}`;
  let query = null;
  try {
    switch (csuri.scheme) {
      case "postgres":
        const dbResult = await fetchPgDatabases(csuri);
        if (dbResult?.err != null) {
          return new Promise((resolve, _) =>
            resolve(
              `${dbEntry} - failed obtaining postgres databases, err=${dbResult.err.message}, ${JSON.stringify(dbResult.err)}`,
            ),
          );
        }
        query = postgresRoles[roleName]({
          user: userRoleName,
          password: password,
        });
        console.log(
          `${dbEntry} - start provisioning roles and privileges, databases=(${dbResult.items.length}), ${dbResult.items}`,
        );
        for (dbname of dbResult.items) {
          const pgClient = new pg.Client({
            ssl: process.env.PGSSLROOTCERT ? {
              ca: fs.readFileSync(process.env.PGSSLROOTCERT).toString(),
            } : false,
            host: csuri.firstHost.host,
            port: csuri.firstHost.port,
            user: csuri.username,
            password: csuri.password,
            database: dbname,
            application_name: user_prefix,
            connectionTimeoutMillis: defaultConnectTimeoutMs,
          });
          // it could blow up with uncaught exception
          // https://github.com/brianc/node-postgres/issues/1927
          await pgClient.connect();
          _ = await pgClient.query(query).catch((ex) => {
            pgClient.end();
            throw ex;
          });
          await pgClient.end();
          return new Promise((resolve, _) => resolve(null));
        }
      case "mysql":
        console.log(`${dbEntry} - start provisioning roles and privileges`);
        query = mysqlRoles[roleName]({ user: userRoleName, password: password });
        const conn = mysql.createConnection({
          host: csuri.firstHost.host,
          port: csuri.firstHost.port,
          user: csuri.username,
          password: csuri.password,
          database: "mysql",
          connectTimeout: defaultConnectTimeoutMs,
          multipleStatements: true,
        });
        conn.connect();
        const queryFn = util.promisify(conn.query).bind(conn);
        _ = await queryFn(query).catch((ex) => {
          conn.end();
          throw ex;
        });
        conn.end();
        return new Promise((resolve, _) => resolve(null));
      case "mongodb-atlas":
        console.log(
          `${dbEntry} - start provisioning roles and privileges (atlas api)`,
        );
        if (!csv.atlas_group_id) {
          throw new Error(`missing atlas group id (project id)`);
        }

        requestPayload = mongodbAtlasRoles[roleName]({
          user: userRoleName,
          password: password,
          atlasGroupID: csv.atlas_group_id,
          dbIdentifier: csv.db_identifier,
        });
        let uri = `${baseAtlasAPIUrl}/groups/${csv.atlas_group_id}/databaseUsers/admin/${userRoleName}`;
        let res = await httpRequest("PATCH", uri, requestPayload);

        // user does not exists
        if (res.status == 404) {
          uri = `${baseAtlasAPIUrl}/groups/${csv.atlas_group_id}/databaseUsers`;
          res = await httpRequest("POST", uri, requestPayload);
        }
        if (res.status > 399) {
          throw new Error(
            `unable to update or create user, status=${res.status}, body=${res.data}`,
          );
        }
        return new Promise((resolve, _) => resolve(null));
      default:
        return new Promise((resolve, _) =>
          resolve(`database scheme ${csuri.scheme} not implemented`),
        );
    }
  } catch (ex) {
    return new Promise((resolve, _) => resolve(ex));
  }
}

async function execStepFnCommand(obj) {
  try {
    if (process.env.SFN_ARN == "") {
      throw new Error(`SFN_ARN environment variable is empty`);
    }

    const sfnClient = new SFNClient();
    const command = new StartExecutionCommand({
      stateMachineArn: process.env.SFN_ARN,
      input: JSON.stringify(obj),
    });
    const res = await sfnClient.send(command);
    return new Promise((resolve, _) => resolve({
      payload: {
        statusCode: res.$metadata.httpStatusCode,
        requestID: res.$metadata.requestId,
        executionArn: res.executionArn,
        startDate: res.startDate.toISOString(),
      },
      err: null,
    }));
  } catch (ex) {
    return new Promise((resolve, _) => resolve({
      payload: null,
      err: ex,
    }));
  }
}

function generateRandomPassword() {
  characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  return Array.from(crypto.webcrypto.getRandomValues(new Uint32Array(30)))
    .map((x) => characters[x % characters.length])
    .join("");
}

function parse_uri(uri) {
  const connectionStringParser = new RegExp(
    "^\\s*" + // Optional whitespace padding at the beginning of the line
    "([^:]+)://" + // Scheme (Group 1)
    "(?:([^:@,/?=&]+)(?::([^:@,/?=&]+))?@)?" + // User (Group 2) and Password (Group 3)
    "([^@/?=&]+)" + // Host address(es) (Group 4)
    "(?:/([^:@,/?=&]+)?)?" + // Endpoint (Group 5)
    "(?:\\?([^:@,/?]+)?)?" + // Options (Group 6)
    "\\s*$", // Optional whitespace padding at the end of the line
    "gi");
  const result = {};

  if (!uri.includes("://")) {
    return result
    // throw new Error(`No scheme found in URI ${uri}`);
  }

  const tokens = connectionStringParser.exec(uri);

  if (Array.isArray(tokens)) {
    result.scheme = tokens[1];
    result.username = tokens[2] ? decodeURIComponent(tokens[2]) : tokens[2];
    result.password = tokens[3] ? decodeURIComponent(tokens[3]) : tokens[3];
    result.hosts = _parseAddress(tokens[4]);
    result.firstHost = {
      host: result.hosts[0]?.host,
      port: result.hosts[0]?.port?.toString(),
    }
    result.endpoint = tokens[5] ? decodeURIComponent(tokens[5]) : tokens[5];
    result.options = tokens[6] ? _parseOptions(tokens[6]) : tokens[6];
  }
  return result;
}

function _parseAddress(addresses) {
  return addresses.split(",")
    .map((address) => {
      const i = address.indexOf(":");

      return (i >= 0 ?
        { host: decodeURIComponent(address.substring(0, i)), port: address.substring(i + 1) } :
        { host: decodeURIComponent(address) });
    });
}

function _parseOptions(options)  {
  const result = {};
  options.split("&")
    .forEach((option) => {
      const i = option.indexOf("=");
      if (i >= 0) {
        result[decodeURIComponent(option.substring(0, i))] = decodeURIComponent(option.substring(i + 1));
      }
    });
  return result;
}

function normalizeDbIdentifier(dbIdentifier) {
  return dbIdentifier.
    replace('-', '_').
      toLowerCase().
      replace(/[^a-zA-Z_ ]/g, "")
}

(async () => {
  const summary = [];
  try {
    // 1. load csv configuration from stdin by default
    // 2. or use CSV_FILE env file path
    // 3. or use the file path from script arguments
    let csvFile = 0;
    if (process.env.CSV_FILE != "") {
      console.log("loaded csv file from env CSV_FILE");
      csvFile = process.env.CSV_FILE;
    } else if (process.argv.length > 2) {
      console.log("loaded csv file from arguments");
      csvFile = process.argv[2];
    } else {
      console.log("loaded csv file from stdin");
    }

    const vaultClient = await newVaultClient(
      process.env.VAULT_ADDR,
      process.env.VAULT_ROLE_ID,
      process.env.VAULT_SECRET_ID,
    );
    const dbinstances = openCsvConfig(csvFile);

    if (Array.from(dbinstances).length == 0) {
      console.log("csv file with invalid format or missing records");
      process.exit(1);
    }

    for (const [i, csv] of dbinstances.entries()) {
      const uri = parse_uri(csv.connection_string)
      const dbEntry = `${uri.scheme}/${uri.firstHost.host}`;
      summary[i] = {
        record: dbEntry,
        error: '',
        db_identifier: csv.db_identifier,
        business_unit: csv.business_unit,
        engine: uri.scheme == "mongodb-atlas" ? "mongo" : uri.scheme,
        owner_email: csv.owner_email,
        cto_email: csv.cto_email,
        vault_keys: {}
      };
      console.log(`--> ${dbEntry} - starting provisioning roles`);

      if (csv.action != "create" && csv.action != "upsert") {
        summary[i].error = `unknown action ${csv.action}`
        console.log(
          `${dbEntry} - skip record, unknown action: ${csv.action}, accept=[create, upsert]`,
        );
        continue;
      }

      if (uri.scheme != "mongodb-atlas") {
        const err = await checkLiveness(uri.firstHost.host, uri.firstHost.port);
        // skip databases that failed to connect
        if (err) {
          console.log(
            `${dbEntry} - not ready at port ${uri.firstHost.port}, reason=${err}`,
          );
          summary[i].error = `liveness check error`;
          continue;
        }
        console.log(`${dbEntry} - database ready at port ${uri.firstHost.port}`);
      }

      summary[i].roles = {}
      for (roleName of roleList) {
        let userRole = `${user_prefix}_${roleName}`;
        if (uri.scheme == "mongodb-atlas") {
          userRole = `${user_prefix}_${normalizeDbIdentifier(csv.db_identifier)}_${roleName}`;
          if (roleName == adminRole) {
            userRole = `dbre_${normalizeDbIdentifier(csv.db_identifier)}`;
          }
        }
        const vaultPath = `${csv.vault_path_prefix}${userRole}_${uri.firstHost.host}`;
        const roleResult = { error: '', user: userRole, vault_path: vaultPath }

        let { payload, err } = await getVaultSecret(vaultClient, vaultPath);
        console.log(
          `${dbEntry} - vault: fetch secret, path=${vaultPath}, request_id=${payload.requestID}, version=${payload.version}, destroyed=${payload.destroyed}, err=${JSON.stringify(err)}`,
        );
        // action create will not proceed if the secret already exists in Vault
        if (csv.action == "create" && err == null) {
          roleResult.error = 'vault key already exists (action is create)'
          continue;
        }

        // skip it for non 404 errors
        if (err?.statusCode > 0 && err?.statusCode != 404) {
          roleResult.error = `fail to fetch vault key, status=${err.statusCode}`
          continue;
        }

        const randomPasswd = generateRandomPassword();
        err = await provisionRoles(csv, userRole, roleName, randomPasswd);
        console.log(
          `${dbEntry} - finished provisioning roles, error=${err != null}`,
        );
        if (err != null) {
          roleResult.error = "failed provisioning role";
          console.log(
            `${dbEntry} - query error, message=${err.message}, err=${JSON.stringify(err)}`,
          );
          continue;
        }

        const vaultPayload = parseVaultPayload(uri, roleName, userRole, randomPasswd);
        ({ payload, err } = await putVaultSecret(vaultClient, vaultPath, vaultPayload));
        roleResult.error = err != null ? "failed writing secrets into Vault" : "";

        if (err == null && roleName == roRole) {
          const replicas = csv.replicas ? csv.replicas.split(';') : []
          summary[i].dbre_namespace_ro_payload = {}
          for (const [ridx, replicaHost] of replicas.entries()) {
            if (replicaHost == '') {
              continue
            }
            const dbreNamespaceRoVaultPath = `${csv.vault_path_prefix}${user_prefix}_dbre_user_ro_${replicaHost}`;
            const uriReplica = {
              firstHost: { host: replicaHost, port: uri.firstHost.port},
              scheme: uri.scheme,
            }
            const dbreNamespaceRoPayload = parseVaultPayload(uriReplica, "", userRole, randomPasswd);
            ({ payload, err } = await putVaultSecret(vaultClient, dbreNamespaceRoVaultPath, dbreNamespaceRoPayload));
            roleResult.error = err != null ? `failed writing replica secrets (${replicaHost}) into Vault` : "";
            summary[i].dbre_namespace_ro_payload[String(ridx)] = {
              envs: Object.keys(dbreNamespaceRoPayload),
              namespace: dbreNamespaceRoVaultPath.replace('/data/', '/')
            }
            console.log(
              `${dbEntry}/${replicaHost} (replica) - vault: write secret, path=${vaultPath}, request_id=${payload.requestID}, err=${JSON.stringify(err)}`,
            );
          }
        }

        summary[i].status = (summary[i].status == "error" || roleResult.error != "") ? "error" : "ok";
        summary[i].roles[roleName] = roleResult;

        summary[i].vault_keys[uri.scheme == "mongodb-atlas" && roleName == adminRole ? "admin": roleName] = {
          envs: Object.keys(vaultPayload),
          namespace: vaultPath.replace('/data/', '/'),
        }

        console.log(
          `${dbEntry} - vault: write secret, path=${vaultPath}, request_id=${payload.requestID}, err=${JSON.stringify(err)}`,
        );
      }

      // save into Vault admin/dbre credentials
      if (uri.scheme != "mongodb-atlas") {
        const dbreNamespaceVaultPath = `${csv.vault_path_prefix}${user_prefix}_dbre_user_${uri.firstHost.host}`;
        const dbreNamespacePayload = parseVaultPayload(uri, "", uri.username, uri.password);
        ({ payload, err } = await putVaultSecret(vaultClient, dbreNamespaceVaultPath, dbreNamespacePayload));
        summary[i].roles["dbre"] = {
          error: err != null ? "failed writing secrets (dbre_namespace) into Vault" : "",
          user: uri.username, vault_path: dbreNamespaceVaultPath }

        summary[i].status = (summary[i].status == "error" || err != null) ? "error" : "ok";
        summary[i].dbre_namespace_payload = {
          envs: Object.keys(dbreNamespacePayload),
          namespace: dbreNamespaceVaultPath.replace('/data/', '/')
        }
        console.log(
          `${dbEntry}/dbre - vault: write secret, path=${dbreNamespaceVaultPath}, request_id=${payload.requestID}, err=${JSON.stringify(err)}`,
        );
      }
    }

    // configure with aws env vars
    for (const [i, s] of summary.entries()) {
      if (s.status == "ok") {
        console.log(`${s.record} - step function: executing with arn ${process.env.SFN_ARN}`);
        ({ payload, err } = await execStepFnCommand({
          pr: 'Hoop',
          deleted: false, // TODO: add action delete
          application_name: 'Hoop Prod',
          db_identifier: s.db_identifier,
          bu: s.business_unit,
          engine: s.engine,
          vault_keys: Object.assign(s.vault_keys,
            s.engine == 'mongo' ? {} : {
              usr_dbre_namespace_ro: s.dbre_namespace_ro_payload,
              usr_dbre_namespace: s.dbre_namespace_payload,
            }),
          approvers: {
            owner: s.owner_email,
            cto: s.cto_email,
          },
        }))
        summary[i].error = err == null ? "" : "failed executing step functions"
        if (err != null) {
          console.log(`${s.record} - step function: failed executing:`, err);
          continue
        }
        console.log(`${s.record} - step function: response, status=${payload.statusCode}, request_id=${payload.requestID}, exec_arn=${payload.executionArn}, start_date=${payload.startDate}`);
      }
    }
  } catch (e) {
    if (summary.length > 0) {
      logSummary(summary);
    }

    console.trace(e.stack || e);
    process.exit(1);
  }
  logSummary(summary);
  process.exit(0);
})();

function logSummary(summary) {
  console.log("\nSummary ");
  console.log("-------- ");
  for (const s of summary) {
    if (s.error != "") {
      console.log(`${s.record} - error=${s.error}`)
    }
    for (roleName of Object.keys(s.roles)) {
      const r = s.roles[roleName];
      let msg = `${s.record} - user=${r.user}, success=${r.error == ""}`;
      if (r.error != "") {
        msg = `${s.record} - user=${r.user}, success=false, error=${r.error}`;
      }
      console.log(msg)
    }
  }
}