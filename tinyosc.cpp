// This file exists to create a nice static or shared library via cmake
// but can otherwise be omitted if you prefer to compile tinyosc
// directly into your own project.

#define OSC_NET_IGNORE_DEPRECATION_WARNINGS
#define OSC_NET_IMPLEMENTATION
#include "tinyosc-net.hpp"
#include "tinyosc.hpp"
