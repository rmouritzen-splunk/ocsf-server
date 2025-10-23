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

  def start_link(schema_file) do
    GenServer.start_link(__MODULE__, schema_file, name: __MODULE__)
  end

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
                      |> Map.put(:schema_file, schema_file)
                      |> Map.put(:parsed_version, parsed_version)

                    {:ok, schema}
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

  @spec schema() :: map()
  def schema(), do: GenServer.call(__MODULE__, nil)

  @spec version() :: String.t()
  def version(), do: GenServer.call(__MODULE__, :version)

  @spec parsed_version() :: Utils.version_t()
  def parsed_version(), do: GenServer.call(__MODULE__, :parsed_version)

  @spec categories() :: map()
  def categories(), do: GenServer.call(__MODULE__, :categories)

  @spec dictionary() :: map()
  def dictionary(), do: GenServer.call(__MODULE__, :dictionary)

  @spec classes() :: map()
  def classes(), do: GenServer.call(__MODULE__, :classes)

  @spec objects() :: map()
  def objects(), do: GenServer.call(__MODULE__, :objects)

  @spec profiles() :: map()
  def profiles(), do: GenServer.call(__MODULE__, :profiles)

  @spec extensions() :: map()
  def extensions(), do: GenServer.call(__MODULE__, :extensions)

  @spec all_classes() :: map()
  def all_classes(), do: GenServer.call(__MODULE__, :all_classes)

  @spec all_objects() :: map()
  def all_objects(), do: GenServer.call(__MODULE__, :all_objects)

  @impl true
  def handle_call(nil, _from, schema) do
    {:reply, schema, schema}
  end

  def handle_call(key, _from, schema) when is_atom(key) do
    {:reply, schema[key], schema}
  end
end
