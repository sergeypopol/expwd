defmodule Expwd do
  use Bitwise

  @type supported_algs :: :ripemd160 | :sha256 | :sha384 | :sha512

  @supported_hash_algorithms [:ripemd160, :sha256, :sha384, :sha512]

  def supported_hash_algorithms(), do: @supported_hash_algorithms

  @doc """
  Securely compare two strings, in constant time.

  Returns `true` if strings are equals, false otherwise. One of this strings can be a
  `t:Expwd.Hashed.Portable.t/0`.

  ## Example

  ```elixir
  iex> Expwd.secure_compare("V01H2GjdTXE3iqDb+3j1VdbM65+/8QcXcjr9dVuMcYE", "V01H2GjdTXE3iqDb+3j1VdbM65+/8QcXcjr9dVuMcYE")
  true

  iex> Expwd.secure_compare("V01H2GjdTXE3iqDb+3j1VdbM65+/8QcXcjr9dVuMcYE", "ni8fN4rnwavBlbVpRrD/pYcAulaG4pW33fJ")
  false

  iex> Expwd.secure_compare("G9fE1eS9aW+/eap0GjSgZaeAKRK8XlhZDLDu6UV2Q1g", "expwd:sha256:10+X11gPkuoRwXHZ/5uva6bYP7inqfykJ/pMk9dXT8E")
  true

  iex> Expwd.secure_compare("expwd:sha256:aX5jyhAYXJGssY/DFj0PbCj5kj+SviA0d7egOTFrbBw", "3w8C85FRAnUSF68KPgArX6yfGDeS8AP6EpEzyd8UaJ8")
  true

  iex(10)> Expwd.secure_compare("G9fE1eS9aW+/eap0GjSgZaeAKRK8XlhZDLDu6UV2Q1g", "expwd:sha256:10+X11gPkuoRwXHZ/5vva6bYP7inqfykJ/pMk9dXT8E")
  false
  ```
  """
  @spec secure_compare(binary(), binary()) :: boolean()

  def secure_compare(left, "expwd:" <> _ = right) when is_binary(left) do
    hashed_right = Expwd.Hashed.Portable.from_portable(right)

    secure_compare(:crypto.hash(hashed_right.alg, left), hashed_right.hash, 0) == 0
  end

  def secure_compare("expwd:" <> _ = left, right) do
      secure_compare(right, left)
  end

  def secure_compare(left, right) when is_binary(left) and is_binary(right) do
    hashed_left = :crypto.hash(:sha256, left)
    hashed_right = :crypto.hash(:sha256, right)

    secure_compare(hashed_left, hashed_right, 0) == 0
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
