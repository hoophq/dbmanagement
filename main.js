const vault = require("node-vault");
const csvsync = require("csv-parse/sync");
const fs = require("node:fs");
const crypto = require("node:crypto");
const util = require("node:util");
const net = require("net");
const pg = require("pg");
var mysql = require("mysql2");

const user_prefix = "dbmng_hoop";
const defaultConnectTimeoutMs = 7000; // 7s
const roRole = "ro";
const rwRole = "rw";
const adminRole = "admin";
const roleList = [roRole, rwRole, adminRole];

const postgres_roles = {
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
    return postgres_roles[roRole](o);
  },
  [adminRole]: (o) => {
    o.privileges =
      "SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER";
    return postgres_roles[roRole](o);
  },
};

const mysql_roles = {
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
COMMIT;
  `,
  [adminRole]: (o) => `
START TRANSACTION;
DROP USER IF EXISTS '${o.user}';
CREATE USER '${o.user}'@'%' IDENTIFIED BY '${o.password}';
GRANT SELECT, DELETE, UPDATE, INSERT, ALTER, CREATE, DROP ON *.* TO '${o.user}'@'%';
FLUSH PRIVILEGES;
COMMIT;
  `,
};

function checkLiveness(host, port) {
  return new Promise((resolve, _) => {
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
        query = postgres_roles[roleName]({
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
        query = mysql_roles[roleName]({ user: userRole, password: password });
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
    let csvFile = 0;
    if (process.argv.length > 2) {
      csvFile = process.argv[2];
    }
    const csvData = fs.readFileSync(csvFile);
    const dbinstances = csvsync.parse(csvData, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
    });

    if (Array.from(dbinstances).length == 0) {
      console.log("csv file with invalid format or missing records");
      process.exit(1);
    }

    const csvItem = dbinstances[0];
    const vaultClient = await newVaultClient(
      csvItem.vault_addr,
      csvItem.vault_role_id,
      csvItem.vault_secret_id,
    );

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
        // const roleQuery = postgres_roles[role](userRole, randomPasswd);
        err = await provisionRoles(csv, role, randomPasswd);
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
    console.log("\n--> output");
    console.log(JSON.stringify(output, null, 2));

    console.trace(e.stack || e);
    process.exit(1);
  }
  console.log("\n--> output");
  console.log(JSON.stringify(output, null, 2));
})();
