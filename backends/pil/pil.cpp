/*
Copyright (C) 2023 Intel Corporation
Copyright (C) 2023 SiPanda Inc

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

#include "backend.h"
#include "control-plane/p4RuntimeSerializer.h"
#include "frontends/common/applyOptionsPragmas.h"
#include "frontends/common/parseInput.h"
#include "frontends/p4/frontend.h"
#include "frontends/p4/simplify.h"
#include "frontends/p4/simplifyParsers.h"
#include "frontends/p4/simplifySwitch.h"
#include "ir/ir.h"
#include "lib/error.h"
#include "lib/exceptions.h"
#include "lib/gc.h"
#include "lib/log.h"
#include "lib/nullstream.h"
//#include "midend.h"
#include "options.h"
#include "version.h"
#include "midend/actionSynthesis.h"
#include "midend/compileTimeOps.h"
#include "midend/complexComparison.h"
#include "midend/convertEnums.h"
#include "midend/convertErrors.h"
#include "midend/copyStructures.h"
#include "midend/eliminateInvalidHeaders.h"
#include "midend/eliminateNewtype.h"
#include "midend/eliminateSerEnums.h"
#include "midend/eliminateSwitch.h"
#include "midend/eliminateTuples.h"
#include "midend/eliminateTypedefs.h"
#include "midend/expandEmit.h"
#include "midend/expandLookahead.h"
#include "midend/fillEnumMap.h"
#include "midend/flattenHeaders.h"
#include "midend/flattenInterfaceStructs.h"
#include "midend/flattenUnions.h"
#include "midend/hsIndexSimplify.h"
#include "midend/local_copyprop.h"
#include "midend/midEndLast.h"
#include "midend/nestedStructs.h"
#include "midend/noMatch.h"
#include "midend/orderArguments.h"
#include "midend/parserUnroll.h"
#include "midend/predication.h"
#include "midend/removeAssertAssume.h"
#include "midend/removeExits.h"
#include "midend/removeLeftSlices.h"
#include "midend/removeMiss.h"
#include "midend/removeSelectBooleans.h"
#include "midend/removeUnusedParameters.h"
#include "midend/replaceSelectRange.h"
#include "midend/simplifyKey.h"
#include "midend/simplifySelectCases.h"
#include "midend/simplifySelectList.h"
#include "midend/tableHit.h"
#include "midend/validateProperties.h"

int main(int argc, char *const argv[]) {
    setup_gc_logging();
    AutoCompileContext autoPILContext(new PIL::PILContext);
    auto &options = PIL::PILContext::get().options();
    options.langVersion = PIL::PILOptions::FrontendVersion::P4_16;
    options.compilerVersion = version_string();

    if (options.process(argc, argv) != nullptr) {
        options.setInputFile();
    }
    if (::errorCount() > 0) {
        return 1;
    }
    auto hook = options.getDebugHook();
    auto chkprogram = P4::parseP4File(options);
    if (chkprogram == nullptr || ::errorCount() > 0) {
        return 1;
    }

    const IR::P4Program *program = chkprogram;
    if (program == nullptr || ::errorCount() > 0) {
        return 1;
    }
    try {
        P4::P4COptionPragmaParser optionsPragmaParser;
        program->apply(P4::ApplyOptionsPragmas(optionsPragmaParser));
        P4::FrontEnd frontend(hook);
        program = frontend.run(options, program);
    } catch (const Util::P4CExceptionBase &bug) {
        std::cerr << bug.what() << std::endl;
        return 1;
    }
    if (program == nullptr || ::errorCount() > 0) {
        return 1;
    }

    P4::serializeP4RuntimeIfRequired(program, options);

    P4::ReferenceMap refMap;
    P4::TypeMap typeMap;

    const IR::ToplevelBlock *toplevel = nullptr;
    auto evaluator = new P4::EvaluatorPass(&refMap, &typeMap);

    PassManager midEnd = {};
    {
      midEnd.setName("MidEnd");
      //midEnd.addDebugHooks(hooks);
      //program = program->apply(midEnd);
      if (::errorCount() > 0) return -1;

      midEnd.addPasses({
            new P4::RemoveMiss(&refMap, &typeMap),
            new P4::EliminateNewtype(&refMap, &typeMap),
            new P4::EliminateSerEnums(&refMap, &typeMap),
            new P4::EliminateInvalidHeaders(&refMap, &typeMap),
            new P4::OrderArguments(&refMap, &typeMap),
            new P4::TypeChecking(&refMap, &typeMap),
            new P4::SimplifyKey(
                &refMap, &typeMap,
                new P4::OrPolicy(new P4::IsValid(&refMap, &typeMap), new P4::IsLikeLeftValue())),
            new P4::RemoveExits(&refMap, &typeMap),
            new P4::ConstantFolding(&refMap, &typeMap),
            new P4::StrengthReduction(&refMap, &typeMap),
            new P4::SimplifySelectCases(&refMap, &typeMap, true),
            // The lookahead implementation in DPDK target supports only a header instance as
            // an operand, we do not expand headers.
            // Structures expanded here are then processed as base bit type in ConvertLookahead
            // pass in backend.
            new P4::ExpandLookahead(&refMap, &typeMap, nullptr, false),
            new P4::ExpandEmit(&refMap, &typeMap),
            new P4::HandleNoMatch(&refMap),
            new P4::SimplifyParsers(&refMap),
            new P4::StrengthReduction(&refMap, &typeMap),
            new P4::EliminateTuples(&refMap, &typeMap),
            new P4::SimplifyComparisons(&refMap, &typeMap),
            new P4::CopyStructures(&refMap, &typeMap, false /* errorOnMethodCall */),
            new P4::NestedStructs(&refMap, &typeMap),
            new P4::SimplifySelectList(&refMap, &typeMap),
            new P4::RemoveSelectBooleans(&refMap, &typeMap),
            new P4::FlattenHeaders(&refMap, &typeMap),
            new P4::FlattenInterfaceStructs(&refMap, &typeMap),
            new P4::EliminateTypedef(&refMap, &typeMap),
            new P4::HSIndexSimplifier(&refMap, &typeMap),
            new P4::ParsersUnroll(true, &refMap, &typeMap),
            new P4::FlattenHeaderUnion(&refMap, &typeMap),
            new P4::SimplifyControlFlow(&refMap, &typeMap),
            new P4::ReplaceSelectRange(&refMap, &typeMap),
            new P4::MoveDeclarations(),  // more may have been introduced
            new P4::ConstantFolding(&refMap, &typeMap),
            //new P4::LocalCopyPropagation(&refMap, &typeMap, nullptr, policy),
            new PassRepeated({new P4::ConstantFolding(&refMap, &typeMap),
                              new P4::StrengthReduction(&refMap, &typeMap)}),
            new P4::MoveDeclarations(),
            new P4::SimplifyControlFlow(&refMap, &typeMap),
            new P4::SimplifySwitch(&refMap, &typeMap),
            new P4::CompileTimeOperations(),
            new P4::TableHit(&refMap, &typeMap),
            new P4::RemoveLeftSlices(&refMap, &typeMap),
            new P4::TypeChecking(&refMap, &typeMap),
            new P4::EliminateSerEnums(&refMap, &typeMap),
            ///
          new P4::MidEndLast(),
            evaluator,
            new VisitFunctor([&]() { toplevel = evaluator->getToplevelBlock(); })
        });

      program = program->apply(midEnd);

      //toplevel = evaluator->getToplevelBlock();
      assert(toplevel != nullptr);
    }

    // PIL::MidEnd midEnd;
    // midEnd.addDebugHook(hook);
    // try {
    //     toplevel = midEnd.run(options, program);
    //     if (::errorCount() > 1 || toplevel == nullptr) {
    //         return 1;
    //     }
    //     if (toplevel->getMain() == nullptr) {
    //         ::error("Cannot process input file. Program does not contain a 'main' module");
    //         return 1;
    //     }
    //     if (options.dumpJsonFile)
    //         JSONGenerator(*openFile(options.dumpJsonFile, true)) << toplevel << std::endl;
    // } catch (const Util::P4CExceptionBase &bug) {
    //     std::cerr << bug.what() << std::endl;
    //     return 1;
    // }
    // if (::errorCount() > 0) {
    //     return 1;
    // }
    PIL::Backend backend(toplevel, &refMap, &typeMap, options);
    if (!backend.process()) return 1;

    // if (!options.introspecFile.isNullOrEmpty()) {
    //     std::ostream *outIntro = openFile(options.introspecFile, false);
    //     if (outIntro != nullptr) {
    //         // bool serialized = backend.serializeIntrospectionJson(*outIntro);
    //         // if (!serialized) {
    //         //     std::remove(options.introspecFile);
    //         //     return 1;
    //         // }
    //     }
    // }
    if (::errorCount() > 0) {
        return 1;
    }
    if (!options.outputFile.isNullOrEmpty() || !options.cFile.isNullOrEmpty() ||
        !options.introspecFile.isNullOrEmpty()) {
        backend.serialize();
    }
    return ::errorCount() > 0;
}
