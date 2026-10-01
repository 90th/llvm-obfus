__attribute__((noinline)) float protected_float(float value) {
  if (value == 0.0f) return value;
  float scaled = value * 1.5f;
  return scaled > 2.0f ? scaled - 0.25f : scaled + 0.75f;
}

__attribute__((noinline)) double protected_double(double value) {
  if (value == 0.0) return value;
  double scaled = value * 1.5;
  return scaled > 2.0 ? scaled - 0.25 : scaled + 0.75;
}
