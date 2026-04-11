#include <cstdint>
#include <iostream>
#include <string_view>

#if defined(__clang__)
#define OBF_ANNOTATE(tag) __attribute__((annotate(tag)))
#else
#define OBF_ANNOTATE(tag)
#endif

static std::uint32_t OBF_ANNOTATE("obf:strong") mix_token(std::string_view token) {
  std::uint32_t state = 0x31415926u;
  for (unsigned char ch : token) {
    state = (state << 5) ^ (state >> 2) ^ ch ^ 0x55aau;
  }
  return state ^ 0x1337u;
}

static bool OBF_ANNOTATE("obf:strong") verify_license(std::string_view token) {
  constexpr std::string_view expected = "delta-7";
  return token == expected && mix_token(token) != 0;
}

static const char *OBF_ANNOTATE("obf:light") banner(bool granted) {
  return granted ? "ACCESS GRANTED" : "ACCESS DENIED";
}

int main(int argc, char **argv) {
  const std::string_view token = argc > 1 ? argv[1] : "";
  const bool granted = verify_license(token);
  const std::uint32_t score = mix_token(token.empty() ? "guest" : token);

  std::cout << banner(granted) << '\n';
  std::cout << score << '\n';
  return granted ? 0 : 1;
}
