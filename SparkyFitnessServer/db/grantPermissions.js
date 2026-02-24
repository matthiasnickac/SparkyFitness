const { getSystemClient } = require("./poolManager");
const { log } = require("../config/logging");

async function grantPermissions() {
  const client = await getSystemClient();
  const appUser = `"${process.env.SPARKY_FITNESS_APP_DB_USER.replace(/"/g, '""')}"`;

  try {
    log("info", `Ensuring permissions for role: ${appUser}`);

    // Grant usage on schemas
    await client.query(`GRANT USAGE ON SCHEMA public TO ${appUser}`);
    await client.query(`GRANT USAGE ON SCHEMA auth TO ${appUser}`);
    await client.query(`GRANT USAGE ON SCHEMA system TO ${appUser}`);

    // Grant permissions on all tables in the public schema
    await client.query(
      `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${appUser}`,
    );
    await client.query(
      `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${appUser}`,
    );

    // Grant permissions on all sequences in the public schema
    await client.query(
      `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${appUser}`,
    );
    await client.query(
      `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ${appUser}`,
    );

    // Grant permissions on all tables in the auth schema
    await client.query(
      `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO ${appUser}`,
    );
    await client.query(
      `ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${appUser}`,
    );

    // Grant permissions on all functions in the public schema
    await client.query(
      `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ${appUser}`,
    );
    await client.query(
      `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO ${appUser}`,
    );

    // Grant permissions on all functions in the auth schema
    await client.query(`
      DO $$
      DECLARE
          func record;
      BEGIN
          FOR func IN
              SELECT p.oid::regprocedure AS func_signature
              FROM pg_proc p
              JOIN pg_namespace n ON p.pronamespace = n.oid
              WHERE n.nspname = 'public'
              -- The magic line: filter out functions owned by extensions
              AND NOT EXISTS (
                  SELECT 1 FROM pg_depend d
                  WHERE d.objid = p.oid AND d.deptype = 'e'
              )
          LOOP
              EXECUTE 'GRANT EXECUTE ON FUNCTION ' || func.func_signature || ' TO ${appUser}';
          END LOOP;
      END
      $$;
    `);
    await client.query(
      `ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT EXECUTE ON FUNCTIONS TO ${appUser}`,
    );
      

    // Grant select on schema_migrations to check applied migrations
    await client.query(
      `GRANT SELECT ON system.schema_migrations TO ${appUser}`,
    );

    log("info", `Successfully ensured permissions for role: ${appUser}`);
  } catch (error) {
    log("error", "Error granting permissions:", error);
    process.exit(1); // Exit if permissions cannot be granted
  } finally {
    client.release();
  }
}

module.exports = {
  grantPermissions,
};
