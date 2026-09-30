__attribute__((noinline, annotate("obf:strong_vm")))
unsigned secret_vm(unsigned value) {
  unsigned mixed = (value ^ 0x5a5aU) + 17U;
  return mixed * 3U;
}
