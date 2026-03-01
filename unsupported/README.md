# Supported
Items in this directory are no longer supported.

If there is a need to support these again, either file a an issue at https://github.com/ocsf/ocsf-server/issues or create a pull request moving the file(s) back to the base of the repo and fixing them up so they work.

## Testing
**NOTE:** The `mix test` command does, well, something... but nothing useful. It's a relic. Below is the information originally in the base `README.md`.

### Testing local schema changes

You can use `mix test` command to test the changes made to the schema. For example to ensure the JSON files are correct or the attributes are defined.

Assuming the schema repo has been cloned in `../ocsf-schema` directory, then you can test the schema with this command:

```shell
SCHEMA_DIR=../ocsf-schema SCHEMA_EXTENSION=extensions mix test
```

If everything is correct, then you should not see any errors or warnings.
