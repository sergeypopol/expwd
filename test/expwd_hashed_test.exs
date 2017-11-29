defmodule ExpwdHashedTest do
  use ExUnit.Case
  doctest Expwd

  test "hash is valid" do
    assert Expwd.hello() == :world
  end
end
