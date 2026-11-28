defmodule DatadeftAuth.AWS.DynamoDB.Items do
  @moduledoc false

  @u64_max 18_446_744_073_709_551_615

  def required_string(item, name) do
    with {:ok, value} when not is_nil(value) <- optional_string(item, name) do
      {:ok, value}
    else
      _ -> {:error, :internal}
    end
  end

  def optional_string(item, name) do
    case Map.fetch(item, name) do
      :error ->
        {:ok, nil}

      {:ok, %{"S" => value} = attribute} when is_binary(value) and map_size(attribute) == 1 ->
        if String.valid?(value), do: {:ok, value}, else: {:error, :internal}

      _ ->
        {:error, :internal}
    end
  end

  def required_bool(item, name) do
    case Map.fetch(item, name) do
      {:ok, %{"BOOL" => value} = attribute} when is_boolean(value) and map_size(attribute) == 1 ->
        {:ok, value}

      _ ->
        {:error, :internal}
    end
  end

  def required_u64(item, name) do
    with {:ok, value} when not is_nil(value) <- optional_u64(item, name) do
      {:ok, value}
    else
      _ -> {:error, :internal}
    end
  end

  def optional_u64(item, name) do
    case Map.fetch(item, name) do
      :error ->
        {:ok, nil}

      {:ok, %{"N" => value} = attribute} when is_binary(value) and map_size(attribute) == 1 ->
        # Rust u64::from_str accepts a leading + and leading zeroes, but no
        # whitespace, minus, decimal point, exponent, overflow or trailing text.
        if Regex.match?(~r/\A\+?[0-9]+\z/, value) do
          case Integer.parse(value) do
            {integer, ""} when integer <= @u64_max -> {:ok, integer}
            _ -> {:error, :internal}
          end
        else
          {:error, :internal}
        end

      _ ->
        {:error, :internal}
    end
  end
end
