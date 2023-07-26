/*
Copyright (C) 2023 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions
and limitations under the License.
*/

#ifndef BACKENDS_PIL_OPTIONS_H_
#define BACKENDS_PIL_OPTIONS_H_

#include "backends/ebpf/ebpfOptions.h"
#include "frontends/common/options.h"
#include "lib/cstring.h"

namespace PIL {

class PILOptions : public CompilerOptions {
 public:
    // file to output to
    cstring outputFile = nullptr;
    cstring cFile = nullptr;
    cstring introspecFile = nullptr;
    bool DebugOn = false;

    PILOptions() {
        registerOption(
            "-o", "outfile",
            [this](const char *arg) {
                outputFile = arg;
                return true;
            },
            "Write pipeline template output to outfile");
        registerOption(
            "-g", nullptr,
            [this](const char *) {
                DebugOn = true;
                return true;
            },
            "Generates debug information");
        registerOption(
            "-i", "introspecFile",
            [this](const char *arg) {
                introspecFile = arg;
                return true;
            },
            "Write introspection json to the given file");
    }
};

using PILContext = P4CContextWithOptions<PILOptions>;

}  // namespace PIL

#endif /* BACKENDS_PIL_OPTIONS_H_ */
