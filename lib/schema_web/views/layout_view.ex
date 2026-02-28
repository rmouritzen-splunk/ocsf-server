defmodule SchemaWeb.LayoutView do
  use SchemaWeb, :view

  @spec sort_profiles(map()) :: list()
  def sort_profiles(profiles) do
    Enum.sort(
      profiles,
      fn {_, profile1}, {_, profile2} ->
        caption1 = profile1[:caption]
        caption2 = profile2[:caption]

        cond do
          caption1 < caption2 ->
            true

          caption1 == caption2 ->
            profile1[:extension] <= profile2[:extension]

          true ->
            false
        end
      end
    )
  end

  @spec format_profile(map()) :: String.t()
  def format_profile(profile) do
    Enum.reduce(profile[:attributes], [], fn {name, _}, acc ->
      [Atom.to_string(name) | acc]
    end)
    |> Enum.join("\n")
  end

  @spec format_profile_postfix(map()) :: String.t()
  def format_profile_postfix(profile) do
    if profile[:extension] != nil and profile[:extension] != "" do
      "<sup class='source-indicator-small extension-indicator' data-toggle='tooltip' title='From #{profile[:extension]} extension'><i class='fas fa-layer-group'></i></sup>"
    else
      ""
    end
  end

  def format_extension(extension) do
    caption = "#{extension[:caption]}"
    uid = " [#{extension[:uid]}]"

    case extension[:version] do
      nil ->
        [caption, uid]

      ext_ver ->
        [caption, uid, "</br>", "v", ext_ver]
    end
  end

  def select_versions(_conn) do
    current = Schema.version()

    case Schemas.versions() do
      [] ->
        [
          "<option value='",
          current,
          "' selected=true disabled=true>",
          "v#{current}",
          "</option>"
        ]

      versions ->
        Enum.map(versions, fn {version, _path} ->
          [
            "<option value='",
            "/#{version}",
            if version == current do
              "' selected=true disabled=true>"
            else
              "'>"
            end,
            "v#{version}",
            "</option>"
          ]
        end)
    end
  end
end
