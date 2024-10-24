const vault = require("node-vault");
const csvsync = require("csv-parse/sync");
const fs = require("node:fs");
const crypto = require("node:crypto");
const util = require("node:util");
const urllib = require("urllib");
const net = require("net");
const pg = require("pg");
const mysql = require("mysql2");

const user_prefix = "dbmng_hoop";
const defaultConnectTimeoutMs = 7000; // 7s
const roRole = "ro";
const rwRole = "rw";
const adminRole = "admin";
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
    o.roles = [{ databaseName: "admin", roleName: "readAnyDatabase" }];
    return {
      username: o.user,
      password: o.password,
      description: `Provisioned by ${user_prefix}`,
      labels: [],
      scopes: [],
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
      { databaseName: "admin", roleName: "readWriteAnyDatabase" },
      { databaseName: "admin", roleName: "userAdminAnyDatabase" },
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
    if (
      csv.db_type != "mongodb-atlas" &&
      csv.db_type != "mysql" &&
      csv.db_type != "postgres"
    ) {
      errors.push(
        `record=${index} wrong db_type (${csv.db_type}), accept (postgres, mysql or mongodb-atlas)`,
      );
    }
    if (csv.db_type == "mongodb-atlas" && csv.atlas_group_id == "") {
      errors.push(`record=${index} missing atlas_group_id attribute`);
    }

    if (csv.db_type == "mysql" || csv.db_type == "postgres") {
      for (attr of [
        "db_host",
        "db_port",
        "db_admin_user",
        "db_admin_password",
      ]) {
        if (csv[attr] == "") {
          errors.push(
            `record=${index} ${attr} is required when db_type is mysql or postgres`,
          );
        }
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
      Accept: "application/vnd.atlas.2023-01-01+json", // update date to desired API version
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

async function fetchPgDatabases(host, port, user, password) {
  const dbItems = [];
  try {
    const pgClient = new pg.Client({
      ssl: false,
      host: host,
      port: port,
      user: user,
      password: password,
      database: "postgres",
      application_name: user_prefix,
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
  let { version, initialized, sealed } = await vaultClient.health(options);
  console.log(
    `--> Vault connected at ${addr}, version=${version}, initialized=${initialized}, sealed=${sealed}`,
  );
  return vaultClient;
}

async function provisionRoles(csv, roleName, password) {
  const userRole = `${user_prefix}_${roleName}`;
  const dbEntry = `${csv.db_type}/${csv.db_host}`;
  let query = null;
  try {
    switch (csv.db_type) {
      case "postgres":
        const dbResult = await fetchPgDatabases(
          csv.db_host,
          csv.db_port,
          csv.db_admin_user,
          csv.db_admin_password,
        );
        if (dbResult?.err != null) {
          return new Promise((resolve, _) =>
            resolve(
              `${dbEntry} - failed obtaining postgres databases, err=${dbResult.err.message}, ${JSON.stringify(dbResult.err)}`,
            ),
          );
        }
        query = postgresRoles[roleName]({
          user: userRole,
          password: password,
        });
        console.log(
          `${dbEntry} - start provisioning roles and privileges, databases=(${dbResult.items.length}), ${dbResult.items}`,
        );
        for (dbname of dbResult.items) {
          const pgClient = new pg.Client({
            ssl: false,
            host: csv.db_host,
            port: csv.db_port,
            user: csv.db_admin_user,
            password: csv.db_admin_password,
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
        query = mysqlRoles[roleName]({ user: userRole, password: password });
        const conn = mysql.createConnection({
          host: csv.db_host,
          port: csv.db_port,
          user: csv.db_admin_user,
          password: csv.db_admin_password,
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
        const atlasGroupID = csv.atlas_group_id ? csv.atlas_group_id : "";
        if (atlasGroupID == "") {
          throw new Error(`missing atlas group id (project id)`);
        }

        requestPayload = mongodbAtlasRoles[roleName]({
          user: userRole,
          password: password,
          atlasGroupID: atlasGroupID,
        });
        let uri = `${baseAtlasAPIUrl}/groups/${atlasGroupID}/databaseUsers/admin/${userRole}`;
        let res = await httpRequest("PATCH", uri, requestPayload);

        // user does not exists
        if (res.status == 404) {
          uri = `${baseAtlasAPIUrl}/groups/${atlasGroupID}/databaseUsers`;
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
          resolve(`database type ${csv.db_type} not implemented`),
        );
    }
  } catch (ex) {
    return new Promise((resolve, _) => resolve(ex));
  }
}

function generateRandomPassword() {
  characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  return Array.from(crypto.webcrypto.getRandomValues(new Uint32Array(30)))
    .map((x) => characters[x % characters.length])
    .join("");
}

(async () => {
  const output = [];
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
      const dbEntry = `${csv.db_type}/${csv.db_host}`;
      output[i] = { record: dbEntry, status: "initial" };
      console.log(`--> ${dbEntry} - starting provisioning roles`);

      if (csv.action != "create" && csv.action != "upsert") {
        output[i].status = "skip:unknown-action";
        console.log(
          `${dbEntry} - skip record, unknown action: ${csv.action}, accept=[create, upsert]`,
        );
        continue;
      }

      if (csv.db_type != "mongodb-atlas") {
        const err = await checkLiveness(csv.db_host, csv.db_port);
        // skip databases that failed to connect
        if (err) {
          console.log(
            `${dbEntry} - not ready at port ${csv.db_port}, reason=${err}`,
          );
          output[i].status = "db:liveness-failed";
          continue;
        }
        console.log(`${dbEntry} - database ready at port ${csv.db_port}`);
      }

      for (role of roleList) {
        const userRole = `${user_prefix}_${role}`;
        const vaultPath = `${csv.vault_path_prefix}${csv.db_type}/${csv.db_host}/${userRole}`;
        let { payload, err } = await getVaultSecret(vaultClient, vaultPath);

        console.log(
          `${dbEntry} - vault: fetch secret, path=${vaultPath}, request_id=${payload.requestID}, version=${payload.version}, destroyed=${payload.destroyed}, err=${JSON.stringify(err)}`,
        );
        // action create will not proceed if the secret already exists in Vault
        if (csv.action == "create" && err == null) {
          output[i].status = "skip:vault-key-exists";
          continue;
        }

        output[i].user = userRole;
        output[i].vault_path = vaultPath;
        // skip it for non 404 errors
        if (err?.statusCode > 0 && err?.statusCode != 404) {
          output[i].status = "vault:fetch-failure";
          continue;
        }

        const randomPasswd = generateRandomPassword();
        err = await provisionRoles(csv, role, randomPasswd);
        console.log(
          `${dbEntry} - finished provisioning roles, error=${err != null}`,
        );
        if (err != null) {
          output[i].status = "db:query-error";
          console.log(
            `${dbEntry} - query error, message=${err.message}, err=${JSON.stringify(err)}`,
          );
          continue;
        }

        ({ payload, err } = await putVaultSecret(vaultClient, vaultPath, {
          HOST: csv.db_host,
          PORT: csv.db_port,
          USER: userRole,
          PASSWORD: randomPasswd,
        }));
        output[i].status = err == null ? "success" : "vault:write-failure";

        console.log(
          `${dbEntry} - vault: write secret, path=${vaultPath}, request_id=${payload.requestID}, err=${JSON.stringify(err)}`,
        );
      }
    }
  } catch (e) {
    if (output.length > 0) {
      console.log("\n--> output");
      console.log(JSON.stringify(output, null, 2));
    }

    console.trace(e.stack || e);
    process.exit(1);
  }
  console.log("\n--> output");
  console.log(JSON.stringify(output, null, 2));
})();
