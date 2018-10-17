defmodule Expwd do
  use Bitwise

  @type supported_algs :: :ripemd160 | :sha256 | :sha384 | :sha512

  @supported_hash_algorithms [:ripemd160, :sha256, :sha384, :sha512]

  def supported_hash_algorithms(), do: @supported_hash_algorithms

  @doc """
  Securely compare two strings, in constant time.

  Returns `true` if strings are equals, false otherwise

  ## Example

  ```elixir
  iex> Expwd.secure_compare("V01H2GjdTXE3iqDb+3j1VdbM65+/8QcXcjr9dVuMcYE", "V01H2GjdTXE3iqDb+3j1VdbM65+/8QcXcjr9dVuMcYE")
  true

  iex> Expwd.secure_compare("V01H2GjdTXE3iqDb+3j1VdbM65+/8QcXcjr9dVuMcYE", "ni8fN4rnwavBlbVpRrD/pYcAulaG4pW33fJ")
  false

  iex> Expwd.secure_compare("JBCi34pS0x+c9UZEj4itWa9JSqt1UQj9/rfULmpHTRY", %Expwd.Hashed{
  ...> alg: :sha256,
  ...> hash: <<205, 221, 101, 226, 145, 163, 216, 198, 62, 105, 203, 181, 200, 103,
  ...>      13, 217, 120, 77, 212, 27, 113, 80, 122, 148, 104, 73, 29, 200, 97, 58,
  ...>      143, 60>>
  ...> })
  false

  iex> Expwd.secure_compare("JBCi34pS0x+c9UZEj4itWa9JSqt1UQj9/rfULmpHTRY", %Expwd.Hashed{
  ...> alg: :sha256,
  ...> hash: <<142, 86, 170, 80, 19, 174, 138, 223, 133, 24, 247, 61, 116, 248, 37,
  ...>      220, 95, 61, 87, 104, 65, 70, 30, 106, 78, 90, 181, 165, 67, 110, 117,
  ...>      142>>
  ...> })
  true

  ```
  """
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
