defmodule Expwd.Hashed do
  @moduledoc """
  Documentation for Expwd.
  """

  @type t :: %__MODULE__{
    alg: atom(),
    hash: binary()
  }

  @enforce_keys [:alg, :hash]
  defstruct [:alg, :hash]

  @spec new() :: {String.t, t}
  def new() do
    pwd = Base.encode64(:crypto.strong_rand_bytes(32), padding: false)

    {
      pwd,
      %__MODULE__{
        alg: :sha256,
        hash: :crypto.hash(:sha256, pwd)
      }
    }
  end

  @spec gen(binary, Expwd.supported_algs) :: t
  def gen(password, alg \\ :sha256)
  def gen(password, alg) do
    if alg not in Expwd.supported_hash_algorithms()
    do
      raise Expwd.UnsupportedHashAlgorithm, message: "Unsupported hash algorithm #{alg}"
    end

    %__MODULE__{
      alg: alg,
      hash: :crypto.hash(alg, password)
    }
  end

  @spec to_string(t) :: String.t
  def to_string(%Expwd.Hashed{alg: alg, hash: hash}) do
    ":expwd:#{alg}:#{Base.encode64(hash, padding: false)}"
  end
end
