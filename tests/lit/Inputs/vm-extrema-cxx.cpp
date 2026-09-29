#include <algorithm>

extern "C" __attribute__((noinline)) int cpp_smax(int lhs, int rhs) {
  return std::max(lhs, rhs);
}

extern "C" __attribute__((noinline)) unsigned cpp_umax(unsigned lhs, unsigned rhs) {
  return std::max(lhs, rhs);
}

int main() {
  volatile int smallest = -1;
  volatile int largest = 1;
  return cpp_smax(smallest, largest) != 1 || cpp_smax(largest, smallest) != 1 ||
                 cpp_umax(static_cast<unsigned>(smallest), static_cast<unsigned>(largest)) !=
                     static_cast<unsigned>(-1) ||
                 cpp_umax(static_cast<unsigned>(largest), static_cast<unsigned>(smallest)) !=
                     static_cast<unsigned>(-1);
}
