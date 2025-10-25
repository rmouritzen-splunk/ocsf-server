# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
defmodule Schema do
  @moduledoc """
  Schema keeps the contexts that define your domain
  and business logic.

  Contexts are also responsible for managing your data, regardless
  if it comes from the database, an external API or others.
  """
  alias Schema.SingleRepo
  alias Schema.Utils

  @dialyzer :no_improper_lists

  @doc """
    Returns the schema version string.
  """
  @spec version() :: String.t()
  def version() do
    SingleRepo.version()
  end

  @spec parsed_version() :: Utils.version_t()
  def parsed_version() do
    SingleRepo.parsed_version()
  end

  @spec server_version() :: String.t()
  def server_version() do
    Application.spec(:schema_server)
    |> Keyword.get(:vsn)
    |> to_string()
    |> String.trim_trailing("-SNAPSHOT")
  end

  @doc """
    Returns the schema extensions.
  """
  @spec extensions() :: map()
  def extensions() do
    SingleRepo.extensions()
  end

  @doc """
    Returns the schema profiles.
  """
  @spec profiles() :: map()
  def profiles() do
    SingleRepo.profiles()
  end

  @spec profiles_filter_extensions(Utils.string_set_t() | nil) :: map()
  def profiles_filter_extensions(extensions) do
    SingleRepo.profiles() |> Utils.filter_items_by_extensions(extensions)
  end

  @doc """
    Reloads the event schema without the extensions.
  """
  @spec reload() :: :ok
  def reload() do
    SingleRepo.reload()
  end

  @doc """
    Reloads the event schema with extensions from the given path.
  """
  @spec reload(String.t() | list()) :: :ok
  def reload(path) do
    SingleRepo.reload(path)
  end

  @doc """
    Returns the event categories defined in the given extension set.
  """
  @spec categories_filter_extensions(Utils.string_set_t() | nil) :: map()
  def categories_filter_extensions(extensions) do
    schema = SingleRepo.schema()

    schema[:categories]
    |> Map.update!(:attributes, fn attributes ->
      Utils.filter_items_by_extensions(attributes, extensions)
      |> Enum.into(%{}, fn {category_name, _category} ->
        {
          category_name,
          category_with_classes_filter_extension(schema, Utils.to_uid(category_name), extensions)
        }
      end)
    end)
  end

  @spec category_filter_extensions(
          String.t(),
          Utils.string_set_t() | nil
        ) :: nil | Utils.category_t()
  def category_filter_extensions(id, extensions) do
    category_with_classes_filter_extension(SingleRepo.schema(), Utils.to_uid(id), extensions)
  end

  @doc """
    Returns the attribute dictionary.
  """
  @spec dictionary() :: Utils.dictionary_t()
  def dictionary() do
    SingleRepo.dictionary()
  end

  @doc """
    Returns the attribute dictionary including the extension.
  """
  @spec dictionary(Utils.string_set_t()) :: Utils.dictionary_t()
  def dictionary(extensions) do
    SingleRepo.dictionary()
    |> Map.update!(:attributes, fn attributes ->
      Utils.filter_items_by_extensions(attributes, extensions)
    end)
  end

  @doc """
    Returns the data types defined in dictionary.
  """
  @spec data_types :: map()
  def data_types() do
    SingleRepo.dictionary()[:types]
  end

  @spec data_type?(String.t(), String.t() | list(String.t())) :: boolean()
  def data_type?(type, type) do
    true
  end

  def data_type?(type, base_type) when is_binary(base_type) do
    types = Map.get(data_types(), :attributes)

    case Map.get(types, String.to_atom(type)) do
      nil -> false
      data -> data[:type] == base_type
    end
  end

  def data_type?(type, base_types) do
    types = Map.get(data_types(), :attributes)

    case Map.get(types, String.to_atom(type)) do
      nil ->
        false

      data ->
        t = data[:type] || type
        Enum.any?(base_types, fn b -> b == t end)
    end
  end

  @doc """
    Returns all event classes.
  """
  @spec classes() :: map()
  def classes() do
    SingleRepo.classes()
  end

  @spec classes_filter_extensions(Utils.string_set_t() | nil) :: map()
  def classes_filter_extensions(extensions) do
    SingleRepo.classes() |> Utils.filter_items_by_extensions(extensions)
  end

  @spec classes_filter_extensions_profiles(
          Utils.string_set_t() | nil,
          Utils.string_set_t() | nil
        ) :: map()
  def classes_filter_extensions_profiles(extensions, profiles) do
    classes_filter_extensions(extensions)
    |> Utils.filter_items_attributes_by_profiles(profiles)
  end

  @spec all_classes() :: map()
  def all_classes() do
    SingleRepo.all_classes()
  end

  @spec all_objects() :: map()
  def all_objects() do
    SingleRepo.all_objects()
  end

  @doc """
    Returns a single event class.
  """
  @spec class(atom() | String.t()) :: nil | Utils.class_t()
  def class(id) do
    SingleRepo.classes()[Utils.to_uid(id)]
  end

  @doc """
    Returns class with attributes filtered by profiles.
  """
  @spec class_filter_profiles(
          String.t(),
          Utils.string_set_t() | nil
        ) :: nil | map()
  def class_filter_profiles(id, nil) do
    SingleRepo.classes()[Utils.to_uid(id)]
  end

  def class_filter_profiles(id, profiles) do
    case SingleRepo.classes()[Utils.to_uid(id)] do
      nil ->
        nil

      class ->
        Map.update!(class, :attributes, fn attributes ->
          Utils.filter_attributes_by_profiles(attributes, profiles)
        end)
    end
  end

  @doc """
  Finds a class by the class uid value.
  """
  @spec find_class(integer()) :: nil | Utils.class_t()
  def find_class(uid) when is_integer(uid) do
    case Enum.find(SingleRepo.classes(), fn {_, class} -> class[:uid] == uid end) do
      {_, class} -> class
      nil -> nil
    end
  end

  @spec objects_filter_extensions(Utils.string_set_t() | nil) :: map()
  def objects_filter_extensions(extensions) do
    SingleRepo.objects() |> Utils.filter_items_by_extensions(extensions)
  end

  @doc """
    Returns a single object.
  """
  @spec object(atom | String.t()) :: nil | Utils.object_t()
  def object(id) do
    SingleRepo.objects()[Utils.to_uid(id)]
  end

  @spec object_filter_extensions(String.t(), Utils.string_set_t() | nil) :: nil | map()
  defp object_filter_extensions(id, extensions) when is_binary(id) do
    SingleRepo.objects()[Utils.to_uid(id)]
    |> Utils.filter_item_links_by_extensions(extensions)
  end

  @spec object_filter_extensions_profiles(
          String.t(),
          Utils.string_set_t() | nil,
          Utils.string_set_t() | nil
        ) :: nil | map()
  def object_filter_extensions_profiles(id, extensions, nil) do
    object_filter_extensions(id, extensions)
  end

  def object_filter_extensions_profiles(id, extensions, profiles) do
    case object_filter_extensions(id, extensions) do
      nil ->
        nil

      object ->
        Map.update!(object, :attributes, fn attributes ->
          Utils.filter_attributes_by_profiles(attributes, profiles)
        end)
    end
  end

  # ------------------#
  # Export Functions #
  # ------------------#

  @spec export_schema_filter_extensions_profiles(
          Utils.string_set_t() | nil,
          Utils.string_set_t() | nil
        ) :: %{
          base_event: map(),
          classes: map(),
          objects: map(),
          types: map(),
          dictionary_attributes: map(),
          version: String.t()
        }
  def export_schema_filter_extensions_profiles(extensions, profiles) do
    schema = SingleRepo.clean_schema()
    # Oddly, class and object attributes are not filtered

    classes =
      schema[:classes]
      |> Utils.filter_items_by_extensions(extensions)
      |> Utils.filter_items_attributes_by_profiles(profiles)

    objects =
      schema[:objects]
      |> Utils.filter_items_by_extensions(extensions)
      |> Utils.filter_items_attributes_by_profiles(profiles)

    dictionary_attributes =
      schema[:dictionary][:attributes]
      |> Map.update!(:attributes, fn attributes ->
        Utils.filter_items_by_extensions(attributes, extensions)
      end)

    %{
      base_event: classes[:base_event],
      classes: classes,
      objects: objects,
      types: schema[:dictionary][:types][:attributes],
      dictionary_attributes: dictionary_attributes,
      version: schema[:version]
    }
  end

  @doc """
    Exports the data types.
  """
  @spec export_data_types :: any
  def export_data_types() do
    SingleRepo.clean_dictionary()[:types][:attributes]
  end

  @spec export_classes_filter_extensions_profiles(
          Utils.string_set_t() | nil,
          Utils.string_set_t() | nil
        ) :: map()
  def export_classes_filter_extensions_profiles(extensions, nil) do
    SingleRepo.clean_classes()
    |> Utils.filter_items_by_extensions(extensions)
  end

  def export_classes_filter_extensions_profiles(extensions, profiles) do
    SingleRepo.clean_classes()
    |> Utils.filter_items_by_extensions(extensions)
    |> Utils.filter_items_attributes_by_profiles(profiles)
  end

  @spec export_base_event_filter_profiles(Utils.string_set_t() | nil) :: map()
  def export_base_event_filter_profiles(nil) do
    SingleRepo.clean_classes()[:base_event]
  end

  def export_base_event_filter_profiles(profiles) do
    SingleRepo.clean_classes()[:base_event]
    |> Utils.filter_item_attributes_by_profiles(profiles)
  end

  @spec export_objects_filter_extensions_profiles(
          Utils.string_set_t(),
          Utils.string_set_t() | nil
        ) :: map()
  def export_objects_filter_extensions_profiles(extensions, nil) do
    SingleRepo.clean_objects()
    |> Utils.filter_items_by_extensions(extensions)
  end

  def export_objects_filter_extensions_profiles(extensions, profiles) do
    SingleRepo.clean_objects()
    |> Utils.filter_items_by_extensions(extensions)
    |> Utils.filter_items_attributes_by_profiles(profiles)
  end

  # ----------------------------#
  # Enrich Event Data Functions #
  # ----------------------------#

  def enrich(data, enum_text, observables) do
    Schema.Helper.enrich(data, enum_text, observables)
  end

  # -------------------------------#
  # Generate Sample Data Functions #
  # -------------------------------#

  @doc """
  Returns a randomly generated sample event, based on the spcified profiles.
  """
  @spec generate_event(Utils.class_t(), Utils.string_set_t() | nil) :: map()
  def generate_event(class, profiles) when is_map(class) do
    Schema.Generator.generate_sample_event(class, profiles)
  end

  @doc """
  Returns randomly generated sample object data.
  """
  @spec generate_object(Utils.object_t() | atom() | binary()) :: any()
  def generate_object(type) when is_map(type) do
    Schema.Generator.generate_sample_object(type, nil)
  end

  def generate_object(type) do
    Schema.object(type) |> Schema.Generator.generate_sample_object(nil)
  end

  @doc """
  Returns randomly generated sample object data, based on the spcified profiles.
  """
  @spec generate_object(Utils.object_t(), Utils.string_set_t() | nil) :: map()
  def generate_object(type, profiles) when is_map(type) do
    Schema.Generator.generate_sample_object(type, profiles)
  end

  @spec category_with_classes_filter_extension(
          map(),
          atom(),
          Utils.string_set_t() | nil
        ) :: map() | nil
  defp category_with_classes_filter_extension(schema, id, extensions) do
    case schema[:categories][:attributes][id] do
      nil ->
        nil

      category ->
        classes =
          schema[:classes]
          |> Utils.filter_items_by_extensions(extensions)
          |> Map.delete(:attributes)
          |> Map.delete(:associations)

        category_uid = Atom.to_string(id)

        list =
          classes
          |> Stream.filter(fn {_name, class} ->
            cat = Map.get(class, :category)
            cat == category_uid or Utils.to_uid(class[:extension], cat) == id
          end)
          |> Stream.map(fn {name, class} ->
            class =
              class
              |> Map.delete(:category)
              |> Map.delete(:category_name)

            {name, class}
          end)
          |> Enum.to_list()

        Map.put(category, :classes, list)
        |> Map.put(:name, category_uid)
    end
  end

  @spec reduce_class(map) :: map
  def reduce_class(data) do
    delete_attributes(data) |> delete_associations()
  end

  @spec delete_attributes(map) :: map
  def delete_attributes(data) do
    Map.delete(data, :attributes)
  end

  @spec delete_associations(map) :: map
  defp delete_associations(data) do
    Map.delete(data, :associations)
  end

  @spec delete_links(map) :: map
  def delete_links(data) do
    Map.delete(data, :_links)
  end
end
