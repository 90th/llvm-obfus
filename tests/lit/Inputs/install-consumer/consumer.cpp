#include "api.h"
#include <iostream>
#include <string>
#include <vector>

int main() {
  size_t required = 0;
  if (package_copy_v1(1, nullptr, 0, &required) != OBF_STRING_COPY_NEED_CAPACITY ||
      required != 32)
    return 1;
  std::vector<char> buffer(required + 1, '\x5a');
  if (package_copy_v1(1, buffer.data(), required, &required) != OBF_STRING_COPY_OK ||
      required != 32 || buffer.back() != '\x5a' ||
      std::string(buffer.data()) != "installed authenticated payload" ||
      package_mix(37) != UINT64_C(687925))
    return 2;
  std::cout << "C++: " << buffer.data() << " mix=687925\n";
  return 0;
}
