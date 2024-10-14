const vault = require("node-vault");
const csvsync = require("csv-parse/sync");
const fs = require("node:fs");
const crypto = require("node:crypto");
var net = require("net");
var pg = require("pg");

const user_prefix = "dbmng";

const postgres_roles = {
  ro: (user, password) => `
DO $$
    DECLARE
        role_count int;
BEGIN
    SELECT COUNT(*) INTO role_count FROM pg_roles WHERE rolname = '${user}';
    IF role_count = 0 THEN
        CREATE ROLE "${user}" WITH LOGIN ENCRYPTED PASSWORD '${password}' NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER;
        GRANT USAGE ON SCHEMA public TO "${user}";
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO "${user}";
    END IF;
END$$;`,
  rw: (user, password) => `
DO $$
    DECLARE
        role_count int;
BEGIN
    SELECT COUNT(*) INTO role_count FROM pg_roles WHERE rolname = '${user}';
    IF role_count = 0 THEN
        CREATE ROLE "${user}" WITH LOGIN ENCRYPTED PASSWORD '${password}' NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER;
        GRANT USAGE ON SCHEMA public TO "${user}";
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "${user}";
    END IF;
END$$;`,
  admin: (user, password) => `
DO $$
    DECLARE
        role_count int;
BEGIN
    SELECT COUNT(*) INTO role_count FROM pg_roles WHERE rolname = '${user}';
    IF role_count = 0 THEN
        CREATE ROLE "${user}" WITH LOGIN ENCRYPTED PASSWORD '${password}' NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER;
        GRANT USAGE ON SCHEMA public TO "${user}";
        GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public TO "${user}";
    END IF;
END$$;`,
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

async function fetchPGDatabases(host, port, user, password) {
  const pgclient = new pg.Client({
    ssl: false,
    host: host,
    port: port,
    user: user,
    password: password,
    database: "postgres",
    application_name: "dbmng",
    connectionTimeoutMillis: 10000, // 10s
  });

  await pgclient.connect();
  let res = await pgclient.query(
    "SELECT datname as dbname FROM pg_database WHERE datname NOT IN ('postgres', 'template0', 'template1', 'rdsadmin')",
  );

  await pgclient.end();
  if (res.rowCount == 0) {
    return [];
  }
  const dbItems = [];
  for (row of res.rows) {
    dbItems.push(row.dbname);
  }
  return dbItems;
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
    const res = vaultClient
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
    opts.token = secretID;
  }
  let { version, initialized, sealed } = await vaultClient.health();
  console.log(
    `--> Vault connected at ${addr}, version=${version}, initialized=${initialized}, sealed=${sealed}`,
  );
  return vaultClient;
}

async function doPgQuery(pgClient, query) {
  return new Promise((resolve, _) => {
    pgClient
      .query(query)
      .then((res) => resolve({ payload: res, err: null }))
      .catch((ex) => resolve({ payload: null, err: ex }));
  });
}

function outputFromCsvEntry(entry) {
  return {
    action: entry.action,
    deleted: false,
    application_name: "Hoop",
    bu: entry.business_unit,
    vault_keys: {},
    engine: entry.db_type,
    approvers: {
      owner: entry.owner_email,
      cto: entry.cto_email,
    },
  };
}

function generateRandomPassword() {
  characters =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";
  return Array.from(crypto.webcrypto.getRandomValues(new Uint32Array(30)))
    .map((x) => characters[x % characters.length])
    .join("");
}

(async () => {
  try {
    let csvFile = 0;
    if (process.argv.length > 2) {
      csvFile = process.argv[2];
    }
    // const csvFile = process.argv[2];
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

    for (obj of dbinstances) {
      if (obj.action != "create" && obj.action != "upsert") {
        console.log(
          `skip record, unknown action ${obj.action}, accept=[create, upsert]`,
        );
        continue;
      }
      const err = await checkLiveness(obj.db_host, obj.db_port);
      // skip databases that failed to connect
      if (err) {
        console.log(
          `${obj.db_type} not ready at ${obj.db_host}:${obj.db_port}, reason=${err}`,
        );
        continue;
      }
      console.log(
        `--> database ${obj.db_type} ready at ${obj.db_host}:${obj.db_port}`,
      );

      const dbList = await fetchPGDatabases(
        obj.db_host,
        obj.db_port,
        obj.db_admin_user,
        obj.db_admin_password,
      );

      const output = outputFromCsvEntry(obj);
      for (const dbname of dbList) {
        output[dbname] = {};
        const pgclient = new pg.Client({
          ssl: false,
          user: obj.db_admin_user,
          password: obj.db_admin_password,
          port: obj.db_port,
          host: obj.db_host,
          database: dbname,
          application_name: "dbmng",
          connectionTimeoutMillis: 10000, // 10s
        });
        await pgclient.connect();
        console.log(
          `--> provisioning default roles=${Object.keys(postgres_roles)}, db=${dbname}, host=${obj.db_host}`,
        );

        for (role of ["ro", "rw", "admin"]) {
          const userRole = `${user_prefix}_${dbname}_${role}`;
          console.log(`--> provisioning role ${userRole}`);

          const vaultPath = `${obj.vault_path_prefix}${obj.db_type}/${obj.db_host}/${userRole}`;
          let { payload, err } = await getVaultSecret(vaultClient, vaultPath);
          // let { payload, err } = res;

          console.log(
            `vault: fetch secret, path=${vaultPath}, request_id=${payload.requestID}, version=${payload.version}, destroyed=${payload.destroyed}, err=${JSON.stringify(err)}`,
          );
          // action create will not proceed if the secret already exists in Vault
          if (obj.action == "create" && err == null) {
            continue;
          }
          output[dbname][role] = {
            user: userRole,
            status: "initial",
          };
          // skip it for non 404 errors
          if (err?.statusCode > 0 && err?.statusCode != 404) {
            output[dbname][role].status = "vault:fetch-failure";
            continue;
          }

          // TODO: change to random password
          const randomPasswd = generateRandomPassword();
          const roleQuery = postgres_roles[role](userRole, randomPasswd);
          ({ payload, err } = await doPgQuery(pgclient, roleQuery));
          if (err != null) {
            output[dbname][role].status = "pg:query-error";
            console.log(
              `pg: query error, message=${err.message}, err=${JSON.stringify(err)}`,
            );
            continue;
          }

          ({ payload, err } = await putVaultSecret(vaultClient, vaultPath, {
            HOST: obj.db_host,
            PORT: obj.db_port,
            USER: userRole,
            PASSWORD: randomPasswd,
          }));
          output[dbname][role].status =
            err == null ? "success" : "vault:write-failure";

          console.log(
            `vault: write secret, path=${vaultPath}, request_id=${payload.requestID}, err=${JSON.stringify(err)}`,
          );
        }
        _ = await pgclient.end();
      }
      console.log("--> output");
      console.log(JSON.stringify(output, null, 2));
    }
  } catch (e) {
    console.trace(e.stack || e);
    process.exit(1);
  }
})();
