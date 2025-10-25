# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
defmodule Schema.SingleRepo do
  use GenServer

  alias Schema.Utils
  require Logger

  @spec start_link(any()) :: :ignore | {:error, any()} | {:ok, pid()}
  def start_link(schema_file) do
    GenServer.start_link(__MODULE__, schema_file, name: __MODULE__)
  end

  # The state in this module is a map:
  #   %{
  #     schema: <map() - schema with extra information needed for schema browser UI>,
  #     clean_schema: <map() - schema without extra schema browser UI information},
  #     parsed_version: <Utils.vertion_t()>,
  #     schema_file: <String.t() - path to loaded schema>
  #   }
  # The clean schema is created from the browser schema once when initializing to simplify
  # processing and avoid sending the larger schema across Elixir (Erlang) process boundaries.

  @impl true
  @spec init(String.t()) :: {:ok, map()} | {:error, String.t()}
  def init(schema_file) when is_binary(schema_file) do
    case File.read(schema_file) do
      {:ok, json} ->
        case Jason.decode(json, keys: :atoms) do
          {:ok, schema} ->
            case validate_schema(schema) do
              :ok ->
                case Utils.parse_version(schema[:version]) do
                  {:error, error_message, original_version} ->
                    {
                      :error,
                      "Invalid \"version\" value #{inspect(original_version)} in" <>
                        " schema file #{inspect(schema_file)}: #{error_message}"
                    }

                  parsed_version ->
                    Logger.info("Schema file       : #{schema_file}")
                    Logger.info("Schema version    : #{schema[:version]}")
                    ext_json = Jason.encode!(schema[:extensions], pretty: true)
                    Logger.info("Schema extensions : #{ext_json}")

                    schema =
                      schema
                      # Profiles do _not_ use atom keys, probably because profiles from extensions
                      # use extension-scoped keys.
                      |> Map.update!(:profiles, fn profiles ->
                        Enum.into(profiles, %{}, fn {name, profile} ->
                          {Atom.to_string(name), profile}
                        end)
                      end)

                    clean_schema = clean_schema(schema)

                    state = %{
                      schema: schema,
                      clean_schema: clean_schema,
                      parsed_version: parsed_version,
                      schema_file: schema_file
                    }

                    {:ok, state}
                end

              {:error, reason} ->
                {
                  :error,
                  "Schema file failed validation #{inspect(schema_file)}: #{reason}"
                }
            end

          {:error, reason} ->
            message = Jason.DecodeError.message(reason)
            {:error, "Failed to JSON decode schema file #{inspect(schema_file)}: #{message}"}
        end

      {:error, reason} ->
        {:error, "Failed to read schema file #{inspect(schema_file)}: #{reason}"}
    end
  end

  def init(nil) do
    {:error, "No schema file supplied"}
  end

  @spec validate_schema(map()) :: :ok | {:error, String.t()}
  defp validate_schema(schema) when is_map(schema) do
    cond do
      not Map.has_key?(schema, :compile_version) ->
        {
          :error,
          "\"compile_version\" key is missing but should have value of 1" <>
            " - is this a compiled schema?"
        }

      schema[:compile_version] != 1 ->
        {
          :error,
          "\"compile_version\" value of 1 is required but got #{inspect(schema[:compile_version])}"
        }

      not Map.has_key?(schema, :browser_mode?) ->
        {:error, "\"browser_mode?\" key is missing but must be set to true"}

      schema[:browser_mode?] != true ->
        {
          :error,
          "\"browser_mode?\" must be set to true but got #{inspect(schema[:browser_mode?])}"
        }

      true ->
        :ok
    end
  end

  defp validate_schema(_) do
    {:error, "Schema file does not contain a JSON object"}
  end

  defp clean_schema(schema) do
    # The following are not enriched with schema browser UI information,
    # so do not need to be cleaned:
    #   schema[:version] (this is just a string)
    #   schema[:categories]
    #   schema[:extensions]
    #   schema[:dictionary][:types]
    %{
      version: schema[:version],
      categories: schema[:categories],
      dictionary: schema[:dictionary] |> Utils.clean_item(),
      classes: Utils.clean_items(schema[:classes]),
      objects: Utils.clean_items(schema[:objects]),
      profiles: Utils.clean_items(schema[:profiles]),
      extensions: schema[:extensions]
    }
  end

  @spec parsed_version() :: Utils.version_t()
  def parsed_version(), do: GenServer.call(__MODULE__, :parsed_version)

  @spec schema() :: map()
  def schema(), do: GenServer.call(__MODULE__, {:schema, nil})

  @spec version() :: String.t()
  def version(), do: GenServer.call(__MODULE__, {:schema, :version})

  @spec categories() :: map()
  def categories(), do: GenServer.call(__MODULE__, {:schema, :categories})

  @spec dictionary() :: map()
  def dictionary(), do: GenServer.call(__MODULE__, {:schema, :dictionary})

  @spec classes() :: map()
  def classes(), do: GenServer.call(__MODULE__, {:schema, :classes})

  @spec objects() :: map()
  def objects(), do: GenServer.call(__MODULE__, {:schema, :objects})

  @spec profiles() :: map()
  def profiles(), do: GenServer.call(__MODULE__, {:schema, :profiles})

  @spec extensions() :: map()
  def extensions(), do: GenServer.call(__MODULE__, {:schema, :extensions})

  @spec all_classes() :: map()
  def all_classes(), do: GenServer.call(__MODULE__, {:schema, :all_classes})

  @spec all_objects() :: map()
  def all_objects(), do: GenServer.call(__MODULE__, {:schema, :all_objects})

  @spec clean_schema() :: map()
  def clean_schema(), do: GenServer.call(__MODULE__, {:clean_schema, nil})

  @spec clean_categories() :: map()
  def clean_categories(), do: GenServer.call(__MODULE__, {:clean_schema, :categories})

  @spec clean_dictionary() :: map()
  def clean_dictionary(), do: GenServer.call(__MODULE__, {:clean_schema, :dictionary})

  @spec clean_classes() :: map()
  def clean_classes(), do: GenServer.call(__MODULE__, {:clean_schema, :classes})

  @spec clean_objects() :: map()
  def clean_objects(), do: GenServer.call(__MODULE__, {:clean_schema, :objects})

  @spec clean_profiles() :: map()
  def clean_profiles(), do: GenServer.call(__MODULE__, {:clean_schema, :profiles})

  @spec reload() :: :ok | {:error, String.t()}
  def reload() do
    GenServer.call(__MODULE__, {:reload, nil})
  end

  @spec reload(String.t()) :: :ok | {:error, String.t()}
  def reload(path) do
    GenServer.call(__MODULE__, {:reload, path})
  end

  @impl true
  def handle_call(:parsed_version, _from, state) do
    {:reply, state[:parsed_version], state}
  end

  def handle_call({:schema, nil}, _from, state) do
    {:reply, state[:schema], state}
  end

  def handle_call({:clean_schema, nil}, _from, state) do
    {:reply, state[:clean_schema], state}
  end

  def handle_call({:schema, key}, _from, state) when is_atom(key) do
    {:reply, state[:schema][key], state}
  end

  def handle_call({:clean_schema, key}, _from, state) when is_atom(key) do
    {:reply, state[:clean_schema][key], state}
  end

  def handle_call({:reload, nil}, _from, state) do
    case init(state[:schema_file]) do
      {:ok, state} ->
        {:reply, :ok, state}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:reload, path}, _from, state) do
    case init(path) do
      {:ok, state} ->
        {:reply, :ok, state}

      error ->
        {:reply, error, state}
    end
  end
end
