defmodule Expwd.Hashed do
  @moduledoc """
  Documentation for Expwd.
  """

  @type t :: %__MODULE__{
    alg: atom(),
    hash: binary(),
    salt: binary
  }

  @enforce_keys [:alg, :hash]
  defstruct [:alg, :hash, :salt]

  @spec gen(binary, atom(), non_neg_integer()) :: t
  def gen(password, alg \\ :sha256, salt_len \\ 16)
  def gen(password, alg, 0) do
    if alg not in Expwd.supported_hash_algorithms()
    do
      raise Expwd.UnsupportedHashAlgorithm, message: "Unsupported hash algorithm #{alg}"
    end

    %__MODULE__{
      alg: alg,
      hash: :crypto.hash(alg, password),
      salt: nil
    }
  end

  def gen(password, alg, salt_len) do
    if alg not in Expwd.supported_hash_algorithms()
    do
      raise Expwd.UnsupportedHashAlgorithm, message: "Unsupported hash algorithm #{alg}"
    end

    salt = gen_salt(salt_len)
    %__MODULE__{
      alg: alg,
      hash: :crypto.hash(alg, salt <> password),
      salt: salt
    }
  end

  defp gen_salt(salt_len), do: :crypto.strong_rand_bytes(salt_len)

  #TODO: define string format
  #defimpl String.Chars, for: Expwd.Hashed do
  #  def to_string(%Expwd.Hashed{alg: alg, hash: hash, salt: nil}) do
  #    "#{alg}:#{Base.encode16(hash)}"
  #  end
  #
  #  def to_string(%Expwd.Hashed{alg: alg, hash: hash, salt: salt}) do
  #    "#{alg}:#{Base.encode16(salt)}$#{Base.encode16(hash)}"
  #  end
  #end
end
