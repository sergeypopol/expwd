defmodule Expwd do
  use Bitwise

  @type supported_algs :: :ripemd160 | :sha256 | :sha384 | :sha512

  @supported_hash_algorithms [:ripemd160, :sha256, :sha384, :sha512]

  def supported_hash_algorithms(), do: @supported_hash_algorithms

  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(left, right) when is_binary(left) and is_binary(right) do
    hashed_left = :crypto.hash(:sha256, left)
    hashed_right = :crypto.hash(:sha256, right)

    secure_compare(hashed_left, hashed_right, 0) == 0
  end

  @spec secure_compare(binary(), Expwd.Hashed.t) :: boolean()
  def secure_compare(left, %Expwd.Hashed{alg: alg, hash: hash} = _right)
    when is_binary(left) and alg in @supported_hash_algorithms do
      secure_compare(:crypto.hash(alg, left), hash, 0) == 0
  end
  def secure_compare(_, %Expwd.Hashed{alg: alg}) when alg not in @supported_hash_algorithms do
    raise Expwd.UnsupportedHashAlgorithm, message: "Unsupported hash algorithm #{alg}"
  end

  @spec secure_compare(Expwd.Hashed.t, binary()) :: boolean()
  def secure_compare(%Expwd.Hashed{} = left, right) do
      secure_compare(right, left)
  end

  @spec secure_compare(binary(), binary(), non_neg_integer) :: non_neg_integer
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
