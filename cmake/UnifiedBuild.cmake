# Options to control unified compilation. More information is available in the
# documentation for `build_unified`.
OPTION (ENABLE_UNIFIED_COMPILATION "Merge source files to speed up compilation" OFF)
set(UNIFIED_SOURCE_CHUNK_SIZE "10" CACHE STRING "Target unified compilation chunk size (an integer or ALL)")

# Helper function: compute `divided / divisor`, round up to the next highest
# integer, and write the result in `output_var`.
function(div_round_up dividend divisor output_var)
  math(EXPR quotient "${dividend} / ${divisor}")
  math(EXPR remainder "${dividend} % ${divisor}")
  if (NOT remainder EQUAL 0)
    math(EXPR quotient "${quotient} + 1")
  endif()
  set(${output_var} ${quotient} PARENT_SCOPE)
endfunction()

# Helper function: determine how a list of `num_items` items should be split
# into chunks of at most `max_chunk_size` items, such that each chunk has as
# close to the same size as possible. We want to do this when generated unified
# sources so that we distribute the "load" between the chunks as evenly as
# possible.
function(select_chunks num_items max_chunk_size num_chunks_out chunk_size_out)
  if (max_chunk_size EQUAL 0)
    set(${num_chunks_out} 1 PARENT_SCOPE)
    set(${chunk_size_out} ${num_items} PARENT_SCOPE)
    return()
  endif()
  div_round_up(${num_items} ${max_chunk_size} num_chunks)
  div_round_up(${num_items} ${num_chunks} chunk_size)
  set(${num_chunks_out} ${num_chunks} PARENT_SCOPE)
  set(${chunk_size_out} ${chunk_size} PARENT_SCOPE)
endfunction(select_chunks)

# Helper function: generate a unified source file called `chunk_filename` that
# will `#include` each of the source files in `sources`.
function(write_chunk_file chunk_filename sources)
  set(chunk_contents "// Unified build source file. Generated by CMake. DO NOT EDIT.\n")

  foreach(source_file IN LISTS ${sources})
    # Determine the absolute path to `source_file`.
    if (IS_ABSOLUTE ${source_file})
      set(source_abs_path ${source_file})
    else()
      set(source_abs_path "${CMAKE_CURRENT_SOURCE_DIR}/${source_file}")
    endif()

    # Convert it to a path relative to the root of the project source tree. It's
    # important to avoid absolute paths in generated C++ code; including them
    # will prevent ccache from reusing results between different checkouts of
    # the same repo.
    file(RELATIVE_PATH source_rel_path ${PROJECT_SOURCE_DIR} ${source_abs_path})

    set(include_directive "#include \"${source_rel_path}\"\n")
    string(CONCAT chunk_contents ${chunk_contents} ${include_directive})
  endforeach(source_file)

  # By using `file(GENERATE ... CONTENT ...)`, we tell cmake to check whether
  # the contents have changed and only overwrite the file if they have. This
  # reduces unnecessary rebuilds.
  file(GENERATE OUTPUT ${chunk_filename} CONTENT ${chunk_contents})
endfunction(write_chunk_file)

# Use unified compilation when building the source files in `sources`. This
# will:
#   - Partition the files in `sources` into chunks.
#   - Generate a unified source file for each chunk; the source file will
#     `#include` each file in the chunk.
#   - Replace the contents of `sources` with the list of unified source files.
#     That means that `sources is both the input and the output to this
#     function.
# The behavior of `build_unified` can be controlled in a number of ways:
#   - The ENABLE_UNIFIED_COMPILATION option can be used to enable or disable it
#     completely. If disabled, this function has no effect.
#   - The UNIFIED_SOURCE_CHUNK_SIZE option can be used to specify a desired
#     chunk size. This can be overridden for a specific invocation of
#     `build_unified` by passing a second parameter. In either case, the value
#     can be either an integer or the string `ALL`, which produces one chunk
#     with all the files in it.
#   - Source files with one of the properties `GENERATED` or `NONUNIFIED` will
#     be built separately, as usual, even if they're passed into
#     `build_unified`. Generated files must always be excluded to avoid breaking
#     dependency tracking, while the NONUNIFIED property allows callers
#     fine-grained control over which files get unified.
function(build_unified sources)
  # The ENABLE_UNIFIED_COMPILATION option is a global switch that turns this
  # feature off. By just returning here, `sources` remains unchanged, and we'll
  # build each file in it individually.
  if (NOT ENABLE_UNIFIED_COMPILATION)
    return()
  endif()

  # This function takes an optional second argument which specifies the maximum
  # chunk size to use. If it's not specified, the global option
  # UNIFIED_SOURCE_CHUNK_SIZE provides the default value.
  if (ARGC GREATER 1)
    set(max_chunk_size_arg ${ARGV1})
  else()
    set(max_chunk_size_arg ${UNIFIED_SOURCE_CHUNK_SIZE})
  endif()

  # The maximum chunk size is either a number, specifying the maximum number of
  # files that should be included in a chunk (we'll get as close to that as we
  # can) or the symbol `ALL`, specifying that all files should be placed a
  # single chunk, no matter how many there are.
  if ("__${max_chunk_size_arg}" STREQUAL "__ALL")
    set(max_chunk_size 0)
  else()
    set(max_chunk_size ${max_chunk_size_arg})
  endif()

  # We transform the name of this function's output variable (which is normally
  # something like `FRONTEND_SRCS`) into a valid base filename (e.g.
  # `unified_frontend_srcs`) which we'll use to name the unified sources we're
  # generating (e.g.  `unified_frontend_srcs_1.cpp`).
  string(MAKE_C_IDENTIFIER ${sources} base_chunk_name_0)
  string(TOLOWER ${base_chunk_name_0} base_chunk_name_1)
  set(base_chunk_filename "${CMAKE_CURRENT_BINARY_DIR}/unified_${base_chunk_name_1}")

  # Separate out any files that are marked as GENERATED (because unifying them
  # will break dependency analysis) or NONUNIFIED (because the user doesn't want
  # to unify them for some other reason). We add them directly to
  # `final_sources_list`, skipping the unified sources generation process.
  set(final_sources_list "")
  set(sources_to_unify "")
  foreach(source_file IN LISTS ${sources})
    get_source_file_property(is_generated ${source_file} GENERATED)
    get_source_file_property(is_nonunified ${source_file} NONUNIFIED)
    if (${is_generated})
      list(APPEND final_sources_list ${source_file})
    elseif(${is_nonunified})
      list(APPEND final_sources_list ${source_file})
    else()
      list(APPEND sources_to_unify ${source_file})
    endif()
  endforeach(source_file)

  list(LENGTH sources_to_unify sources_to_unify_length)
  if (sources_to_unify_length EQUAL 0)
    return()
  endif()

  # Partition the files in `sources_to_unify` into chunks of roughly equal size
  # and generate the unified sources file for each chunk.
  select_chunks(${sources_to_unify_length} ${max_chunk_size} num_chunks chunk_size)
  foreach(chunk RANGE 1 ${num_chunks})
    set(chunk_sources "")
    foreach(chunk_idx RANGE 1 ${chunk_size})
      # Convert from an index into the chunk to an index into the overall list
      # of source files.
      math(EXPR source_idx "(${chunk} - 1) * ${chunk_size} + ${chunk_idx} - 1")

      # We may have run past the end of the list of source files if the chunk
      # size didn't divide the number of source files evenly.
      if (source_idx LESS sources_to_unify_length)
        # Add `sources_to_unify[source_idx]` to the chunk. Because it will be
        # included in a unified sources file, it's now effectively a header, so
        # we need to tell cmake that as well.
        list(GET sources_to_unify ${source_idx} source)
        set_source_files_properties(${source} PROPERTIES HEADER_FILE_ONLY true)
        list(APPEND chunk_sources ${source})
      endif()
    endforeach(chunk_idx)

    # Generate the actual unified sources file and add its filename to the final
    # list of sources we'll return.
    set(chunk_filename "${base_chunk_filename}_${chunk}.cpp")
    list(APPEND final_sources_list ${chunk_filename})
    write_chunk_file(${chunk_filename} chunk_sources)
  endforeach(chunk)

  # All done. Replace the contents of the list that the caller passed to us with
  # the new list of unified sources.
  set(${sources} ${final_sources_list} PARENT_SCOPE)
endfunction(build_unified)
