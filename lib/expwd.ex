defmodule Expwd do
  use Bitwise

  @supported_hash_algorithms [:md5, :ripemd160, :sha, :sha224, :sha256, :sha384, :sha512]

  def supported_hash_algorithms(), do: @supported_hash_algorithms

  # prevents timing attacks
  @spec secure_compare(binary(), binary()) :: :ok | {:error, atom()}
  def secure_compare(left, right) when is_binary(left) and is_binary(right) do
    hashed_left = :crypto.hash(:sha256, left)
    hashed_right = :crypto.hash(:sha256, right)

    if secure_compare(hashed_left, hashed_right, 0) == 0 do
      :ok
    else
      {:error, :no_match}
    end
  end

  @spec secure_compare(binary(), Expwd.Hashed.t) :: :ok | {:error, atom()}
  def secure_compare(left, %Expwd.Hashed{alg: alg, hash: hash, salt: salt} = _right)
    when is_binary(left) and alg in @supported_hash_algorithms do
      hashed_left = if salt != nil do
        :crypto.hash(alg, salt <> left)
      else
        :crypto.hash(alg, left)
      end

      if secure_compare(hashed_left, hash, 0) == 0 do
        :ok
      else
        {:error, :no_match}
      end
  end

  @spec secure_compare(Expwd.Hashed.t, binary()) :: :ok | {:error, atom()}
  def secure_compare(%Expwd.Hashed{alg: alg} = left, right)
    when alg in @supported_hash_algorithms and is_binary(right) do
      secure_compare(right, left, 0) == 0
  end

  @spec secure_compare(Expwd.Hashed.t, binary()) :: :ok | {:error, atom()}
  def secure_compare(%Expwd.Hashed{alg: alg}, _) when alg not in @supported_hash_algorithms do
    raise Expwd.UnsupportedHashAlgorithm, message: "Unsupported hash algorithm #{alg}"
  end

  @spec secure_compare(binary(), Expwd.Hashed.t) :: :ok | {:error, atom()}
  def secure_compare(_, %Expwd.Hashed{alg: alg}) when alg not in @supported_hash_algorithms do
    raise Expwd.UnsupportedHashAlgorithm, message: "Unsupported hash algorithm #{alg}"
  end

  defp secure_compare(<<x, left :: binary>>, <<y, right :: binary>>, acc) do
    secure_compare(left, right, acc ||| (x ^^^ y))
  end

  defp secure_compare(<<>>, <<>>, acc) do
    acc
  end

  defmodule UnsupportedHashAlgorithm do
    defexception [:message]

    @type t :: %__MODULE__{message: String.t}
  end
end
