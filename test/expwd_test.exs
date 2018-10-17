defmodule ExpwdTest do
  use ExUnit.Case
  doctest Expwd

  @tag timeout: 60 * 60000
  test "Constant compare" do
    pwd1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    pwd2 = "a_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    pwd3 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_a"
    pwd4 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa_aaaaaaaaaaaaaaaaaaaaaaaaaaa"

    combos = [
      {pwd1, pwd1},
      {pwd1, pwd2},
      {pwd1, pwd3},
      {pwd1, pwd4},
      {pwd2, pwd1},
      {pwd2, pwd2},
      {pwd2, pwd3},
      {pwd2, pwd4},
      {pwd3, pwd1},
      {pwd3, pwd2},
      {pwd3, pwd3},
      {pwd3, pwd4},
      {pwd4, pwd1},
      {pwd4, pwd2},
      {pwd4, pwd3},
      {pwd4, pwd4}
    ]

    compare_times = Enum.map(
      combos,
      fn {pwda, pwdb} ->
        start_time = :os.system_time()
        secure_compare_n(pwda, pwdb, 100_000)
        end_time = :os.system_time()

        end_time - start_time
      end
    )

    avg = Enum.sum(compare_times) / Enum.count(compare_times)

    assert Enum.max(compare_times) / avg < 1.1 # less than 10% differences
    assert Enum.min(compare_times) / avg > 0.9
  end

  defp secure_compare_n(_, _, 0), do: :ok
  defp secure_compare_n(a, b, n) do
    Expwd.secure_compare(a, b)
    secure_compare_n(a, b, n - 1)
  end

  test "Secure compare" do
    assert Expwd.secure_compare("scgdrfsxzswteztgsderxtgzdgsxtgtsdtzsapkiok",
                                "scgdrfsxzswteztgsderxtgzdgsxtgtsdtzsapkiok")
    refute Expwd.secure_compare("scgdrfsxzswteztgsderxtgzdgsxtgtsdtzsapkiok",
                                "scgdrfsxzswteztqpaorсreqqgsxtgtsdtzsapkiok")
  end
end
