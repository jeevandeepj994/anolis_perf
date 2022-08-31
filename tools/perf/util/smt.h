#ifndef SMT_H
#define SMT_H 1

struct cpu_topology;

/* Returns true if SMT (aka hyperthreading) is enabled. */
bool smt_on(const struct cpu_topology *topology);

#endif
