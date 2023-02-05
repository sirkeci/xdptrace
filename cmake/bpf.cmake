find_program(BPF_CLANG clang REQUIRED)
find_program(BPF_OPT opt REQUIRED)
find_program(BPF_LLC llc REQUIRED)
find_program(BPF_BPFTOOL bpftool REQUIRED)
if(NOT DEFINED CACHE{BPF_TARGET_IS_SUPPORTED})
  execute_process(COMMAND "${BPF_LLC}" -march bpf /dev/null -o /dev/null COMMAND_ERROR_IS_FATAL LAST)
  set(BPF_TARGET_IS_SUPPORTED TRUE CACHE BOOL "Whether compiler supports BPF compilation target.")
endif()

# Debian and derivatives put arch-specific include files under
# /usr/include/<arch>, e.g. /usr/include/x86_64-linux-gnu/.  This dir is
# automatically added to include path in native builds.  It is NOT added
# when targeting BPF.  Figure out the path and later add it explicitly.
#
# Note: Internet suggests installing gcc-multilib, but it is not
# available on aarch64.
find_path(BPF_SYS_INCLUDE asm/types.h REQUIRED)

# There are further complications however, please keep tuned.
# When compiling for 64 bit x86, __x86_64__ preprocessor var is automatically
# defined by the compiler.  When targeting BPF, we get __bpf__ instead.
# Similarly, other variables exist to test for any target platform of
# interest.
#
# Some system headers have their target selection ifdefs messed up.
# We've seen target misdetected, resulting in attempts to include header
# files for foreign architectires that weren't available.
#
# Work around by disabling problematic headers.  This is accomplished by
# adding cmake/bpf/overrides to include path.  The directory is
# considered before system includes.
set(BPF_OVERRIDES_INCLUDE ${CMAKE_SOURCE_DIR}/cmake/bpf/overrides)

# bpf_add_library(target_name file ... [COMPILE_DEFINITIONS ...]
#                                      [INCLUDE_DIRECTORIES ...]) -> ${target_name}.skel.h
#
# Compile C sources and generate BPF skeleton C header file (man bpftool-gen).
# The resulting file is named ${target_name}.skel.h.  To add the directory
# where the generated file is located to the include path, add ${target_name}
# to the target_link_libraries() of the consumer.
#
# CMake include directories, compile definitions, and C flags are NOT
# propagated into the BPF build.
#
# Specify the desired COMPILE_DEFINITIONS, and INCLUDE_DIRECTORIES after
# the respective keyword.
function(bpf_add_library target_name)

  cmake_parse_arguments(PARSE_ARGV 1 BPF_ADD_LIBRARY "" "" "COMPILE_DEFINITIONS;INCLUDE_DIRECTORIES")
  list(TRANSFORM BPF_ADD_LIBRARY_COMPILE_DEFINITIONS PREPEND "-D")
  list(TRANSFORM BPF_ADD_LIBRARY_INCLUDE_DIRECTORIES PREPEND "-I")

  add_library("${target_name}" INTERFACE)

  # Derive artifact path from the source path.  Artifacts are under
  # ${CMAKE_BINARY_DIR}/CMakeFiles/${target_name}.dir, similar to
  # regular object files.
  set(prefix "${CMAKE_BINARY_DIR}/CMakeFiles/${target_name}.dir/")
  function(artifact_path result_var src_path)
    cmake_path(ABSOLUTE_PATH src_path BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" NORMALIZE)
    cmake_path(IS_PREFIX CMAKE_SOURCE_DIR "${src_path}" in_src)
    cmake_path(IS_PREFIX CMAKE_BINARY_DIR "${src_path}" in_bin)
    if(in_src)
      cmake_path(RELATIVE_PATH src_path BASE_DIRECTORY "${CMAKE_SOURCE_DIR}")
    elseif(in_bin)
      cmake_path(RELATIVE_PATH src_path BASE_DIRECTORY "${CMAKE_BINARY_DIR}")
    else()
      cmake_path(GET src_path RELATIVE_PART src_path)
    endif()
    set("${result_var}" "${prefix}g/${src_path}" PARENT_SCOPE)
  endfunction()

  # Compile BPF code into object file.
  function(compile_bpf_obj result_var src_path)
    artifact_path(dest "${src_path}")
    cmake_path(GET dest PARENT_PATH dest_dir)
    cmake_path(REPLACE_EXTENSION dest LAST_ONLY bpf.bc OUTPUT_VARIABLE dest_bc)
    cmake_path(REPLACE_EXTENSION dest LAST_ONLY bpf.o OUTPUT_VARIABLE dest_o)
    cmake_path(REPLACE_EXTENSION dest LAST_ONLY d OUTPUT_VARIABLE dest_dep)
    # Switch to absolute path, otherwise depfile is unusable. 
    cmake_path(ABSOLUTE_PATH src_path BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" NORMALIZE)
    add_custom_command(
      OUTPUT "${dest_bc}"
      MAIN_DEPENDENCY "${src_path}"
      DEPFILE "${dest_dep}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${dest_dir}"
      COMMAND "${BPF_CLANG}" -MD -MF "${dest_dep}"
              -O2 -g -Wall -Wextra -c "${src_path}" -fno-asynchronous-unwind-tables
              ${BPF_ADD_LIBRARY_COMPILE_DEFINITIONS}
              -I "${BPF_OVERRIDES_INCLUDE}"
              -I ${BPF_SYS_INCLUDE} ${BPF_ADD_LIBRARY_INCLUDE_DIRECTORIES}
              -emit-llvm -target bpf -o "${dest_bc}"
    )
    # Don't merge with the prev custom_command, as depfile refers to
    # ${dest_bc} which must match the OUTPUT to be considered.
    add_custom_command(
      OUTPUT "${dest_o}"
      MAIN_DEPENDENCY "${dest_bc}"
      COMMAND "${BPF_LLC}" -march=bpf -mcpu=v3 -mattr=+alu32 --filetype obj "${dest_bc}" -o "${dest_o}"
    )
    set("${result_var}" "${dest_o}" PARENT_SCOPE)
  endfunction()

  # Compile all listed files
  foreach(arg IN LISTS BPF_ADD_LIBRARY_UNPARSED_ARGUMENTS)
    compile_bpf_obj(obj "${arg}")
    list(APPEND objs "${obj}")
  endforeach()

  # "Link" resulting object files
  set(main_o "${prefix}/${target_name}.o")
  add_custom_command(
    OUTPUT "${main_o}"
    DEPENDS ${objs}
    COMMAND "${BPF_BPFTOOL}" gen object "${main_o}" ${objs}
  )

  # Finally, generate the skeleton
  set(includes "${prefix}i/")
  set(skel_h "${includes}${target_name}.skel.h")
  add_custom_command(
    OUTPUT "${skel_h}"
    DEPENDS "${main_o}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${includes}"
    COMMAND "${BPF_BPFTOOL}" gen skeleton "${main_o}" > "${skel_h}"
  )

  # W/o extra custom target, generated files weren't built when an
  # interfacea library user was in a different dir.
  add_custom_target("${target_name}.gen" DEPENDS "${skel_h}")
  target_include_directories("${target_name}" INTERFACE "${includes}")
  add_dependencies("${target_name}" "${target_name}.gen")

endfunction()
