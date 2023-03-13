project(xdptrace)
cmake_minimum_required(VERSION 3.20)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
include(bpf)

bpf_add_library(trace_kern trace_kern.c)
add_executable(xdptrace xdptrace.c prog_meta.c consumer.c xpcapng.c hashmap.c)
target_link_libraries(xdptrace trace_kern bpf)
