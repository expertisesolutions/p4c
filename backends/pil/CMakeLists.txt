#******************************************************************************
# Copyright (C) 2023 Intel Corporation
# Copyright (C) 2023 SiPanda Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions
# and limitations under the License.
#*****************************************************************************/

set(PIL_BACKEND_SOURCES
    backend.cpp
    pil.cpp
    version.cpp
    ../bmv2/common/programStructure.cpp
    ../bmv2/psa_switch/psaProgramStructure.cpp
    )

set(PIL_BACKEND_HEADERS
   backend.h
   version.h
   )

set (IR_DEF_FILES ${IR_DEF_FILES} ${CMAKE_CURRENT_SOURCE_DIR}/pil.def PARENT_SCOPE)

# build
add_executable(p4c-pna-pil ${PIL_BACKEND_SOURCES})
target_link_libraries (p4c-pna-pil ${P4C_LIBRARIES} ${P4C_LIB_DEPS})
add_dependencies(p4c-pna-pil genIR)

# install
install (TARGETS p4c-pna-pil
        RUNTIME DESTINATION ${P4C_RUNTIME_OUTPUT_DIRECTORY})

add_custom_target(linkpil
        COMMAND ${CMAKE_COMMAND} -E create_symlink ${CMAKE_CURRENT_BINARY_DIR}/p4c-pna-pil ${P4C_BINARY_DIR}/p4c-pna-pil
        )

add_dependencies(p4c_driver linkpil)

add_custom_target(pil_includes ALL
  COMMAND ${CMAKE_COMMAND} -E make_directory ${P4C_BINARY_DIR}/p4include/pil
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${P4C_SOURCE_DIR}/p4include/pna.p4 ${P4C_BINARY_DIR}/p4include/pil)

set(PIL_COMPILER_DRIVER "${CMAKE_CURRENT_SOURCE_DIR}/run-pil-test.py")

set (P4_16_SUITES
  "${P4C_SOURCE_DIR}/testdata/pil_samples/*.p4")

p4c_add_tests("pil" ${PIL_COMPILER_DRIVER} "${P4_16_SUITES}" "")
