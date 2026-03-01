# Running the OCSF Server with docker-compose
**NOTE:** The `docker-compose` approach is not currently being actively maintained. It is left in the repo since it may work and may be helpful for some people.

## Development with docker-compose

The `docker-compose` environment enables development without needing to install any dependencies (apart from Docker/Podman and docker-compose) on the development machine.

When run, the standard `_build` and `deps` folders are created, along with a `.mix` folder. If the environment needs to be recreated for whatever reason, the `_build` folder can be removed and `docker-compose` brought down and up again and the environment will automatically rebuild.

### Run the ocsf-server and build the development container
```shell
docker-compose up
```

Then browse to the schema server at http://localhost:8080

### Testing the schema with docker-compose
**NOTE:** it is _not_ necessary to run the server with `docker-compose up` first in order to test the schema (or run any other commands in the development container).

```
# docker-compose run ocsf-elixir mix test
Creating ocsf-server_ocsf-elixir_run ... done
Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg.


Finished in 0.00 seconds (0.00s async, 0.00s sync)
0 failures

Randomized with seed 933777
```

### Set aliases to avoid docker-compose inflicted RSI
```shell
source docker-source.sh
```

### Using aliases to run docker-compose commands
```
# testschema
Creating ocsf-server_ocsf-elixir_run ... done
Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg.


Finished in 0.00 seconds (0.00s async, 0.00s sync)
0 failures

Randomized with seed 636407
```

### Using environment variables to change docker-compose defaults
Optional environment variables can be placed in a `.env` file in the root of the repo to change the default behavior.

An `.env.sample` is provided, and the following options are available:

```
SCHEMA_PATH=../ocsf-schema      # Set the local schema path, eg. ../ocsf-schema, defaults to ../ocsf-schema
OCSF_SERVER_PORT=8080           # Set the port for Docker to listen on for forwarding traffic to the Schema server, defaults to 8080
ELIXIR_VERSION=otp-25-alpine    # Set the Elixir container version for development, defaults to otp-25-alpine
```
