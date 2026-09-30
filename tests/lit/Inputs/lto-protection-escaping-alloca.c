extern void escape(unsigned *);

unsigned protected_calc(unsigned value) {
  unsigned local = value;
  escape(&local);
  return local;
}
