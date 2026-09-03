#include "omni/detail/shellcode.hpp"
#include "test_utils.hpp"

ut::suite<"omni::detail::shellcode"> shellcode_suite = [] {
  "read and write preserve multi-byte values at unaligned offsets"_test = [] {
    constexpr std::uint32_t expected{0x12345678U};
    omni::detail::shellcode<8> shellcode{{0xAA, 0x00, 0x00, 0x00, 0x00, 0xBB, 0x00, 0x00}};

    shellcode.write<std::uint32_t>(1, expected);

    expect(shellcode.read<std::uint32_t>(1) == expected);
    expect(shellcode.read(0) == 0xAA);
    expect(shellcode.read(5) == 0xBB);
  };

  "move construction transfers executable buffer ownership"_test = [] {
    omni::detail::shellcode<1> source{{0xC3}};
    source.setup();

    void* executable_buffer = source.ptr<void>();

    expect(fatal(executable_buffer != nullptr));

    omni::detail::shellcode<1> moved{std::move(source)};

    expect(source.ptr<void>() == nullptr);
    expect(moved.ptr<void>() == executable_buffer);

    moved.execute();
  };

  "move assignment transfers executable buffer ownership"_test = [] {
    omni::detail::shellcode<1> source{{0xC3}};
    source.setup();

    omni::detail::shellcode<1> target{{0xC3}};
    target.setup();

    void* executable_buffer = source.ptr<void>();

    expect(fatal(executable_buffer != nullptr));
    expect(fatal(target.ptr<void>() != nullptr));

    target = std::move(source);

    expect(source.ptr<void>() == nullptr);
    expect(target.ptr<void>() == executable_buffer);

    target.execute();
  };
};
