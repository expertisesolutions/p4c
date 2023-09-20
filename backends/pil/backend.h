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

#ifndef BACKENDS_PIL_BACKEND_H_
#define BACKENDS_PIL_BACKEND_H_

#include "backends/ebpf/psa/ebpfPsaGen.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/parseAnnotations.h"
#include "frontends/p4/parserCallGraph.h"
// #include "introspection.h"
#include "ir/ir.h"
#include "ir/json_parser.h"
#include "lib/error.h"
#include "lib/nullstream.h"
#include "options.h"
#include "pnaProgramStructure.h"
// #include "tcAnnotations.h"
#include <boost/graph/adjacency_list.hpp>

#include "pil_defines.h"

namespace PIL {

extern cstring PnaMainParserInputMetaFields[PIL::MAX_PNA_PARSER_META];
extern cstring PnaMainInputMetaFields[PIL::MAX_PNA_INPUT_META];
extern cstring PnaMainOutputMetaFields[PIL::MAX_PNA_OUTPUT_META];

class PNAEbpfGenerator;

/**
 * Backend code generation from midend IR
 */
class ConvertToBackendIR : public Inspector {
    // using graph_t = boost::adjacency_list<boost::listS, boost::vecS, boost::directedS,
    //                                       boost::property<boost::vertex_name_t, std::string>,
    //                                       boost::property<boost::edge_name_t, std::string>>;

 public:
    const IR::ToplevelBlock *tlb;
    IR::PILPipeline *tcPipeline;
    P4::ReferenceMap *refMap;
    P4::TypeMap *typeMap;
    PILOptions &options;
    unsigned int tableCount = 0;
    unsigned int actionCount = 0;
    unsigned int metadataCount = 0;
    unsigned int labelCount = 0;
    cstring pipelineName = nullptr;
    cstring mainParserName = nullptr;
    ordered_map<cstring, const IR::P4Action *> actions;
    ordered_map<unsigned, cstring> tableIDList;
    ordered_map<unsigned, cstring> actionIDList;
    ordered_map<unsigned, unsigned> tableKeysizeList;
    ordered_map<cstring, std::pair<cstring, int>> stateExtracts;
    ordered_map<cstring, std::tuple<cstring, int, int>> selectExpressions;
    ordered_map<cstring, std::vector<std::pair<cstring, big_int>>> stateMap;


 public:
    ConvertToBackendIR(const IR::ToplevelBlock *tlb, IR::PILPipeline *pipe,
                       P4::ReferenceMap *refMap, P4::TypeMap *typeMap, PILOptions &options)
        : tlb(tlb), tcPipeline(pipe), refMap(refMap), typeMap(typeMap), options(options) {}
    void setPipelineName();
    bool preorder(const IR::P4Program *p) override;
    void postorder(const IR::P4Parser *a) override;
    void postorder(const IR::P4Action *a) override;
    void postorder(const IR::P4Table *t) override;
    void postorder(const IR::P4Program *p) override;
    bool isDuplicateOrNoAction(const IR::P4Action *action);
    void updateDefaultHitAction(const IR::P4Table *t, IR::PILTable *tdef);
    void updateDefaultMissAction(const IR::P4Table *t, IR::PILTable *tdef);
    void updateMatchType(const IR::P4Table *t, IR::PILTable *tabledef);
    bool isPnaParserMeta(const IR::Member *mem);
    bool isPnaMainInputMeta(const IR::Member *mem);
    bool isPnaMainOutputMeta(const IR::Member *mem);
    unsigned int findMappedKernelMeta(const IR::Member *mem);
    const IR::Expression *ExtractExpFromCast(const IR::Expression *exp);
    unsigned getTcType(const IR::StringLiteral *sl);
    unsigned getTableId(cstring tableName) const;
    unsigned getActionId(cstring actionName) const;
    unsigned getTableKeysize(unsigned tableId) const;
    cstring externalName(const IR::IDeclaration *declaration) const;
};

class Backend : public PassManager {
 public:
    const IR::ToplevelBlock *toplevel;
    P4::ReferenceMap *refMap;
    P4::TypeMap *typeMap;
    PILOptions &options;
    IR::PILPipeline *pipeline = new IR::PILPipeline();
    PIL::ConvertToBackendIR *tcIR;
    // PIL::IntrospectionGenerator *genIJ;
    // PIL::ParsePILAnnotations *parsePILAnno;
    const IR::ToplevelBlock *top = nullptr;
    // EbpfOptions ebpfOption;
    EBPF::Target *target;
    const PNAEbpfGenerator *ebpf_program;

 public:
    explicit Backend(const IR::ToplevelBlock *toplevel, P4::ReferenceMap *refMap,
                     P4::TypeMap *typeMap, PILOptions &options)
        : toplevel(toplevel), refMap(refMap), typeMap(typeMap), options(options) {
        setName("BackEnd");
    }
    bool process();
    bool ebpfCodeGen(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
    void serialize() const;
    // bool serializeIntrospectionJson(std::ostream &out) const;
    bool emitCFile();
 private:
   JsonData *toJson() const;
};

}  // namespace PIL

#endif /* BACKENDS_PIL_BACKEND_H_ */
