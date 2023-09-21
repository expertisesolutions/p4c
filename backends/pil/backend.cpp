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

#include "backends/ebpf/ebpfOptions.h"
#include "backends/ebpf/target.h"

namespace PIL {

// const cstring Extern::dropPacket = "drop_packet";
// const cstring Extern::sendToPort = "send_to_port";

cstring pnaMainParserInputMetaFields[PIL::MAX_PNA_PARSER_META] = {"recirculated", "input_port"};

cstring pnaMainInputMetaFields[PIL::MAX_PNA_INPUT_META] = {
    "recirculated", "timestamp", "parser_error", "class_of_service", "input_port"};

cstring pnaMainOutputMetaFields[PIL::MAX_PNA_OUTPUT_META] = {"class_of_service"};

const cstring pnaParserMeta = "pna_main_parser_input_metadata_t";
const cstring pnaInputMeta = "pna_main_input_metadata_t";
const cstring pnaOutputMeta = "pna_main_output_metadata_t";

template <typename T1, typename T2>
std::ostream &operator<<(std::ostream &os, const std::pair<T1, T2> &p) {
    return os << "(" << p.first << ", " << p.second << ")";
}

template <typename... Ts, size_t... I>
void print(std::ostream &os, const std::tuple<Ts...> &t, std::index_sequence<I...>) {
    constexpr auto len = sizeof...(I);
    ((os << std::get<I>(t) << (I == len - 1 ? "" : ", ")), ...);
}

template <typename... Ts>
std::ostream &operator<<(std::ostream &os, const std::tuple<Ts...> t) {
    os << "(";
    print(os, t, std::make_index_sequence<sizeof...(Ts)>());
    return os << ")";
}

bool Backend::process() {
    CHECK_NULL(toplevel);
    if (toplevel->getMain() == nullptr) {
        ::error("main is missing in the package");
        return false;  //  no main
    }
    // auto refMapEBPF = refMap;
    // auto typeMapEBPF = typeMap;
    // parseTCAnno = new ParseTCAnnotations();

    tcIR = new ConvertToBackendIR(toplevel, pipeline, refMap, typeMap, options);

    // genIJ = new IntrospectionGenerator(pipeline, refMap, typeMap);
    addPasses({new P4::ResolveReferences(refMap), new P4::TypeInference(refMap, typeMap), tcIR});

    toplevel->getProgram()->apply(*this);

    for (auto &&[state, argAndType] : tcIR->stateExtracts) {
        std::cout << "(state, v): (" << state << ", " << argAndType << ")" << std::endl;
    }

    for (auto &&[state, nextStates] : tcIR->stateMap) {
        std::cout << "(state, nextStates): (" << state << ", [";
        for (auto &&ns : nextStates) {
            std::cout << ns << ",";
        }
        std::cout << "])" << std::endl;
    }

    for (auto &&[state, typeAndOffset] : tcIR->selectExpressions) {
        std::cout << "(state, typeAndOffset): (" << state << ", " << typeAndOffset << ")"
                  << std::endl;
    }

    if (::errorCount() > 0) return false;

    // if (!ebpfCodeGen(refMapEBPF, typeMapEBPF)) return false;

    auto main = toplevel->getMain();
    if (!main) return false;

    PnaProgramStructure structure(refMap, typeMap);
    auto parsePnaArch = new ParsePnaArchitecture(&structure);

    main->apply(*parsePnaArch);
    // auto evaluator = new P4::EvaluatorPass(refMap, typeMap);
    auto program = toplevel->getProgram();

    // program = program->apply(rewriteToEBPF);

    // map IR node to compile-time allocated resource blocks.
    toplevel->apply(*new BMV2::BuildResourceMap(&structure.resourceMap));

    main = toplevel->getMain();
    if (!main) return false;  // no main
    main->apply(*parsePnaArch);
    program = toplevel->getProgram();

    return true;
}

// bool Backend::ebpfCodeGen(P4::ReferenceMap *refMapEBPF, P4::TypeMap *typeMapEBPF) {
//     if (options.cFile.isNullOrEmpty()) return true;
//     target = new EBPF::KernelSamplesTarget(options.emitTraceMessages);
//     ebpfOption.xdp2tcMode = options.xdp2tcMode;
//     ebpfOption.exe_name = options.exe_name;
//     ebpfOption.file = options.file;
//     PnaProgramStructure structure(refMapEBPF, typeMapEBPF);
//     auto parsePnaArch = new ParsePnaArchitecture(&structure);
//     auto main = toplevel->getMain();
//     if (!main) return false;

//     if (main->type->name != "PNA_NIC") {
//         ::warning(ErrorType::WARN_INVALID,
//                   "%1%: the main package should be called PNA_NIC"
//                   "; are you using the wrong architecture?",
//                   main->type->name);
//         return false;
//     }

//     main->apply(*parsePnaArch);
//     auto evaluator = new P4::EvaluatorPass(refMapEBPF, typeMapEBPF);
//     auto program = toplevel->getProgram();

//     PassManager rewriteToEBPF = {
//         evaluator,
//         new VisitFunctor([this, evaluator, structure]() { top = evaluator->getToplevelBlock();
//         }),
//     };

//     auto hook = options.getDebugHook();
//     rewriteToEBPF.addDebugHook(hook, true);
//     program = program->apply(rewriteToEBPF);

//     // map IR node to compile-time allocated resource blocks.
//     top->apply(*new BMV2::BuildResourceMap(&structure.resourceMap));

//     main = top->getMain();
//     if (!main) return false;  // no main
//     main->apply(*parsePnaArch);
//     program = top->getProgram();

//     EBPF::EBPFTypeFactory::createFactory(typeMapEBPF);
//     auto convertToEbpf = new ConvertToEbpfPNA(ebpfOption, refMapEBPF, typeMapEBPF, tcIR);
//     PassManager toEBPF = {
//         new BMV2::DiscoverStructure(&structure),
//         new InspectPnaProgram(refMapEBPF, typeMapEBPF, &structure),
//         // convert to EBPF objects
//         new VisitFunctor([evaluator, convertToEbpf]() {
//             auto tlb = evaluator->getToplevelBlock();
//             tlb->apply(*convertToEbpf);
//         }),
//     };

//     toEBPF.addDebugHook(hook, true);
//     program = program->apply(toEBPF);

//     ebpf_program = convertToEbpf->getEBPFProgram();

//     return true;
// }

template <typename T>
static T _invertBytes(T val, size_t bytes) {
    T ret = 0;
    for (size_t i = 0; i < bytes; ++i) {
        ret = (ret << 8) | (val & 0xFF);
        val >>= 8;
    }

    return ret;
}

template <typename T, typename F>
static std::string _toFormat(T &&val, F &&format) {
    std::ostringstream oss;
    oss << format << val;

    return oss.str();
}

JsonData *Backend::toJson() const {
    constexpr auto start = "start";
    // const auto &offsetAndLength = tcIR->selectExpressions.at(start);
    JsonObject *json = new JsonObject();
    json->emplace("parsers", new JsonObject({{"name", new JsonString(options.introspecFile)},
                                             {"root-node", new JsonString(start)}}));
    // {
    //   "name": "ether_node",
    //   "min-hdr-length": 14,
    //   "next-proto": {
    //     "field-off": 12,
    //     "field-len": 2,
    //     "table": "ether_table"
    //   }
    // }
    auto *parseNodes = new JsonVector();
    for (auto &&it : tcIR->stateExtracts) {
        auto *node = new JsonObject({{"name", new JsonString(it.first)},
                                     {"min-hdr-length", new JsonNumber(std::get<1>(it.second))}});

        if (auto it_ = tcIR->selectExpressions.find(it.first);
            it_ != tcIR->selectExpressions.end()) {
            const auto &offsetAndLength = it_->second;
            node->emplace(
                "next-proto",
                new JsonObject(
                    {{"field-off", new JsonNumber(std::get<1>(offsetAndLength))},
                     {"field-len", new JsonNumber(std::get<2>(offsetAndLength))},
                     {"table", new JsonString(std::string(it.first.c_str()) + "_table")}}));
        }
        node->emplace("metadata",
                      new JsonObject(
                          {{"ents", new JsonVector({new JsonObject(
                                        {{"name", new JsonString(std::get<2>(it.second))},
                                         {"type", new JsonString("extract")},
                                         {"md-off", new JsonNumber(std::get<3>(it.second))},
                                         {"hdr-src-off", new JsonNumber(0)},
                                         {"length", new JsonNumber(std::get<1>(it.second))}})})}}));
        parseNodes->push_back(node);
    }
    json->emplace("parse-nodes", parseNodes);
    auto protoTables = new JsonVector();
    for (auto &&[state, nextStates] : tcIR->stateMap) {
        auto *table = new JsonObject({{"name", new JsonString(std::string(state) + "_table")}});
        auto *entries = new JsonVector();
        for (auto &&[state_, keyset] : nextStates) {
            const size_t fieldLength = std::get<2>(tcIR->selectExpressions.at(state));
            entries->push_back(new JsonObject(
                {{"node", new JsonString(state_)},
                 {"key", new JsonString(std::string("0x") +
                                        _toFormat(_invertBytes(keyset, fieldLength), std::hex))}}));
        }
        table->emplace("ents", entries);
        protoTables->push_back(table);
    }
    json->emplace("proto-tables", protoTables);

    return json;
}

void Backend::serialize() const {
    if (!options.outputFile.isNullOrEmpty()) {
        auto outstream = openFile(options.outputFile, false);
        if (outstream != nullptr) {
            *outstream << pipeline->toString();
            outstream->flush();
        }
    }
    if (!options.cFile.isNullOrEmpty()) {
        auto cstream = openFile(options.cFile, false);
        if (cstream == nullptr) return;
        if (ebpf_program == nullptr) return;
        EBPF::CodeBuilder c(target);
        // ebpf_program->emit(&c);
        *cstream << c.toString();
        cstream->flush();
    }
    if (!options.introspecFile.isNullOrEmpty()) {
        auto jsonstream = openFile(options.introspecFile, false);
        if (jsonstream != nullptr) {
            // if (true) {
            auto *json = toJson();
            JSONGenerator(*jsonstream) << json << std::endl;
        }
    }
}

// bool Backend::serializeIntrospectionJson(std::ostream &out) const {
//     if (genIJ->serializeIntrospectionJson(out)) {
//         out.flush();
//         return true;
//     }
//     return false;
// }

void ConvertToBackendIR::setPipelineName() {
    cstring path = options.file;
    if (path != nullptr) {
        pipelineName = path;
    } else {
        ::error("filename is not given in command line option");
        return;
    }
    auto fileName = path.findlast('/');
    if (fileName) {
        pipelineName = fileName;
        pipelineName = pipelineName.replace("/", "");
    }
    auto fileext = pipelineName.find(".");
    pipelineName = pipelineName.replace(fileext, "");
    pipelineName = pipelineName.trim();
}

bool ConvertToBackendIR::preorder(const IR::P4Program *p) {
    std::cout << "p4program" << std::endl;
    if (p != nullptr) {
        setPipelineName();
        return true;
    }
    return false;
}

cstring ConvertToBackendIR::externalName(const IR::IDeclaration *declaration) const {
    cstring name = declaration->externalName();
    if (name.startsWith(".")) name = name.substr(1);
    auto Name = name.replace('.', '/');
    return Name;
}

bool ConvertToBackendIR::isDuplicateOrNoAction(const IR::P4Action *action) {
    auto actionName = externalName(action);
    if (actions.find(actionName) != actions.end()) return true;
    if (actionName == P4::P4CoreLibrary::instance().noAction.name) return true;
    return false;
}

void ConvertToBackendIR::postorder(const IR::P4Parser *parser) {
    std::cout << __func__ << " " << __FILE__ << ":" << __LINE__ << " " << typeid(parser).name()
              << std::endl;

    const cstring start = "start";
    for (auto s : parser->states) {
        std::cout << std::endl << s << std::endl;
        const auto stateStr = s->getName().toString();
        for (auto c : s->components) {
            if (auto *p = c->to<IR::MethodCallStatement>()) {
                std::cout << "State method call statement component " << *p << std::endl;
                auto const methodStr = p->methodCall->method->toString();
                if (methodStr.endsWith(".extract")) {
                    const auto *args = p->methodCall->arguments;
                    const auto *typeArgs = p->methodCall->typeArguments;
                    const auto *arg = *args->begin();
                    const auto *typeArg = *typeArgs->begin();
                    // const auto *path = typeArg->path;
                    const auto argStr = arg->toString();
                    const auto typeArgStr = typeArg->toString();
                    const auto typeWidthBytes =
                        typeMap->getTypeType(typeArg, true)->width_bits() >> 3;
                    const auto *member = arg->expression->to<IR::Member>();
                    const auto headerWidthBytes =
                        member->expr->type->to<IR::Type_StructLike>()->width_bits() >> 3;
                    const auto offset = headerWidthBytes - (member->msb() >> 3) - 1;

                    stateExtracts.emplace(
                        stateStr, std::make_tuple(typeArgStr, typeWidthBytes, argStr, offset));
                    std::cout << "Extract " << stateStr << ": " << arg->expression << " (offset "
                              << offset << ") " << typeArg << " " << argStr << std::endl;
                    // std::cout << "Path " << path << std::endl;
                }
                // std::cout << "\n\tMethod " << method->toString();
                // for (auto typeArg : *typeArgs) {
                //     std::cout << "Type argument " << typeArg->toString() << std::endl;
                // }
            } else {
                std::cout << "State irrelevant component " << *c << std::endl;
            }
        }
        if (s->selectExpression) {
            if (auto *p = s->selectExpression->to<IR::PathExpression>()) {
                std::cout << "Path expression " << *p << std::endl;
            } else if (auto *p = s->selectExpression->to<IR::SelectExpression>()) {
                std::cout << "Select expression " << p->select << std::endl;

                for (const auto e : p->select->components) {
                    const auto *m = e->to<IR::Member>();
                    std::cout << "\texpression " << m << " offset " << m->offset_bits()
                              << std::endl;
                    const auto typeStr = std::get<0>(stateExtracts.at(stateStr));
                    const auto widthBytes = std::get<1>(stateExtracts.at(stateStr));
                    selectExpressions.emplace(
                        stateStr, std::make_tuple(typeStr, widthBytes - (m->msb() >> 3) - 1,
                                                  m->type->width_bits() >> 3));
                }

                for (const auto case_ : p->selectCases) {
                    std::cout << "\tcase " << case_;
                    std::cout << "\n\tkeyset " << case_->keyset << " "
                              << case_->keyset->node_type_name();
                    std::cout << "\n\tstate " << case_->state << std::endl;
                    if (auto *constant = case_->keyset->to<IR::Constant>()) {
                        const auto nextStateStr = case_->state->toString();
                        stateMap[stateStr].push_back(std::make_pair(nextStateStr, constant->value));
                    }
                }
            } else {
                std::cout << "unknown expression" << std::endl;
                std::cout << *s->selectExpression << " " << typeid(*s->selectExpression).name()
                          << std::endl;
            }
        }
    }
}

void ConvertToBackendIR::postorder(const IR::P4Action *action) {
    //   std::cout << __func__ << " " << __FILE__ << ":" << __LINE__ << " " << typeid(action).name()
    //   << std::endl;
    if (action != nullptr) {
        if (isDuplicateOrNoAction(action)) return;
        auto actionName = externalName(action);
        // std::cout << "Action name " << actionName << std::endl;
        actions.emplace(actionName, action);
        actionCount++;
        unsigned int actionId = actionCount;
        IR::PILAction *tcAction = new IR::PILAction(actionName);
        tcAction->setPipelineName(pipelineName);
        tcAction->setActionId(actionId);
        actionIDList.emplace(actionId, actionName);
        auto paramList = action->getParameters();
        if (paramList != nullptr && !paramList->empty()) {
            for (auto param : paramList->parameters) {
                auto paramType = typeMap->getType(param);
                // std::cout << "Parameter type " << paramType << std::endl;
                IR::PILActionParam *tcActionParam = new IR::PILActionParam();
                tcActionParam->setParamName(param->name.originalName);
                if (!paramType->is<IR::Type_Bits>()) {
                    ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                            "%1% parameter with type other than bit is not supported", param);
                    return;
                } else {
                    auto paramTypeName = paramType->to<IR::Type_Bits>()->baseName();
                    if (paramTypeName != "bit") {
                        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                                "%1% parameter with type other than bit is not supported", param);
                        return;
                    }
                    tcActionParam->setDataType(PIL::BIT_TYPE);
                    unsigned int width = paramType->to<IR::Type_Bits>()->width_bits();
                    tcActionParam->setBitSize(width);
                }
                // auto annoList = param->getAnnotations()->annotations;
                // for (auto anno : annoList) {
                //     // if (anno->name != ParsePILAnnotations::tcType) continue;
                //     // auto expr = anno->expr[0];
                //     // if (auto typeLiteral = expr->to<IR::StringLiteral>()) {
                //     //     auto val = getTcType(typeLiteral);
                //     //     if (val != PIL::BIT_TYPE) {
                //     //         tcActionParam->setDataType(val);
                //     //     } else {
                //     //         ::error(ErrorType::ERR_INVALID,
                //     //                 "tc_type annotation cannot have '%1%' as value", expr);
                //     //     }
                //     // } else {
                //     //     ::error(ErrorType::ERR_INVALID,
                //     //             "tc_type annotation cannot have '%1%' as value", expr);
                //     // }
                // }
                // tcAction->addActionParams(tcActionParam);
            }
        }
        tcPipeline->addActionDefinition(tcAction);
    }
}

void ConvertToBackendIR::updateDefaultMissAction(const IR::P4Table *t, IR::PILTable *tabledef) {
    //   std::cout << __func__ << " " << __FILE__ << ":" << __LINE__ << " " <<
    //   typeid(tabledef).name() << std::endl;
    auto defaultAction = t->getDefaultAction();
    if (defaultAction == nullptr || !defaultAction->is<IR::MethodCallExpression>()) return;
    auto methodexp = defaultAction->to<IR::MethodCallExpression>();
    auto mi = P4::MethodInstance::resolve(methodexp, refMap, typeMap);
    auto actionCall = mi->to<P4::ActionCall>();
    if (actionCall == nullptr) return;
    auto actionName = externalName(actionCall->action);
    if (actionName != P4::P4CoreLibrary::instance().noAction.name) {
        for (auto tcAction : tcPipeline->actionDefs) {
            if (actionName == tcAction->actionName) {
                tabledef->setDefaultMissAction(tcAction);
                auto defaultActionProperty =
                    t->properties->getProperty(IR::TableProperties::defaultActionPropertyName);
                if (defaultActionProperty->isConstant) {
                    tabledef->setDefaultMissConst(true);
                }
            }
        }
    }
}

void ConvertToBackendIR::updateDefaultHitAction(const IR::P4Table *t, IR::PILTable *tabledef) {
    //   std::cout << __func__ << " " << __FILE__ << ":" << __LINE__ << " " <<
    //   typeid(tabledef).name() << std::endl;
    auto actionlist = t->getActionList();
    if (actionlist != nullptr) {
        unsigned int defaultHit = 0;
        unsigned int defaultHitConst = 0;
        cstring defaultActionName = nullptr;
        for (auto action : actionlist->actionList) {
            // auto annoList = action->getAnnotations()->annotations;
            bool isTableOnly = false;
            bool isDefaultHit = false;
            bool isDefaultHitConst = false;
            // for (auto anno : annoList) {
            //     if (anno->name == IR::Annotation::tableOnlyAnnotation) {
            //         isTableOnly = true;
            //     }
            //     if (anno->name == ParsePILAnnotations::default_hit) {
            //         isDefaultHit = true;
            //         defaultHit++;
            //         auto adecl = refMap->getDeclaration(action->getPath(), true);
            //         defaultActionName = externalName(adecl);
            //     }
            //     if (anno->name == ParsePILAnnotations::default_hit_const) {
            //         isDefaultHitConst = true;
            //         defaultHitConst++;
            //         auto adecl = refMap->getDeclaration(action->getPath(), true);
            //         defaultActionName = externalName(adecl);
            //     }
            // }
            if (isTableOnly && isDefaultHit && isDefaultHitConst) {
                ::error(ErrorType::ERR_INVALID,
                        "Table '%1%' has an action reference '%2%' which is "
                        "annotated with '@tableonly', '@default_hit' and '@default_hit_const'",
                        t->name.originalName, action->getName().originalName);
                break;
            } else if (isTableOnly && isDefaultHit) {
                ::error(ErrorType::ERR_INVALID,
                        "Table '%1%' has an action reference '%2%' which is "
                        "annotated with '@tableonly' and '@default_hit'",
                        t->name.originalName, action->getName().originalName);
                break;
            } else if (isTableOnly && isDefaultHitConst) {
                ::error(ErrorType::ERR_INVALID,
                        "Table '%1%' has an action reference '%2%' which is "
                        "annotated with '@tableonly' and '@default_hit_const'",
                        t->name.originalName, action->getName().originalName);
                break;
            } else if (isDefaultHit && isDefaultHitConst) {
                ::error(ErrorType::ERR_INVALID,
                        "Table '%1%' has an action reference '%2%' which is "
                        "annotated with '@default_hit' and '@default_hit_const'",
                        t->name.originalName, action->getName().originalName);
                break;
            }
        }
        if (::errorCount() > 0) {
            return;
        }
        if ((defaultHit > 0) && (defaultHitConst > 0)) {
            ::error(ErrorType::ERR_INVALID,
                    "Table '%1%' cannot have both '@default_hit' action "
                    "and '@default_hit_const' action",
                    t->name.originalName);
            return;
        } else if (defaultHit > 1) {
            ::error(ErrorType::ERR_INVALID, "Table '%1%' can have only one '@default_hit' action",
                    t->name.originalName);
            return;
        } else if (defaultHitConst > 1) {
            ::error(ErrorType::ERR_INVALID,
                    "Table '%1%' can have only one '@default_hit_const' action",
                    t->name.originalName);
            return;
        }
        if (defaultActionName != nullptr &&
            defaultActionName != P4::P4CoreLibrary::instance().noAction.name) {
            for (auto tcAction : tcPipeline->actionDefs) {
                if (defaultActionName == tcAction->actionName) {
                    tabledef->setDefaultHitAction(tcAction);
                    if (defaultHitConst == 1) {
                        tabledef->setDefaultHitConst(true);
                    }
                }
            }
        }
    }
}

void ConvertToBackendIR::postorder(const IR::P4Table *t) {
    //   std::cout << __func__ << " " << __FILE__ << ":" << __LINE__ << " " << typeid(t).name() <<
    //   std::endl;
    if (t != nullptr) {
        tableCount++;
        unsigned int tId = tableCount;
        auto tName = t->name.originalName;
        // std::cout << "Table name " << t->name.originalName << std::endl;
        tableIDList.emplace(tId, tName);
        auto ctrl = findContext<IR::P4Control>();
        auto cName = ctrl->name.originalName;
        IR::PILTable *tableDefinition = new IR::PILTable(tId, tName, cName, pipelineName);
        auto tEntriesCount = PIL::DEFAULT_TABLE_ENTRIES;
        auto sizeProperty = t->getSizeProperty();
        if (sizeProperty) {
            if (sizeProperty->fitsUint64()) {
                tEntriesCount = sizeProperty->asUint64();
            } else {
                ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                        "table with size %1% cannot be supported", t->getSizeProperty());
                return;
            }
        }
        tableDefinition->setTableEntriesCount(tEntriesCount);
        unsigned int keySize = 0;
        unsigned int keyCount = 0;
        auto key = t->getKey();
        if (key != nullptr && key->keyElements.size()) {
            for (auto k : key->keyElements) {
                auto keyExp = k->expression;
                auto keyExpType = typeMap->getType(keyExp);
                auto widthBits = keyExpType->width_bits();
                keySize += widthBits;
                keyCount++;
            }
        }
        tableDefinition->setKeySize(keySize);
        tableKeysizeList.emplace(tId, keySize);
        // auto annoList = t->getAnnotations()->annotations;
        // for (auto anno : annoList) {
        //     if (anno->name != ParsePILAnnotations::numMask) continue;
        //     auto expr = anno->expr[0];
        //     if (auto val = expr->to<IR::Constant>()) {
        //         tableDefinition->setNumMask(val->asUint64());
        //     } else {
        //         ::error(ErrorType::ERR_INVALID,
        //                 "nummask annotation cannot have '%1%' as value. Only integer "
        //                 "constants are allowed",
        //                 expr);
        //     }
        // }
        auto actionlist = t->getActionList();
        for (auto action : actionlist->actionList) {
            for (auto actionDef : tcPipeline->actionDefs) {
                auto adecl = refMap->getDeclaration(action->getPath(), true);
                auto actionName = externalName(adecl);
                if (actionName != actionDef->actionName) continue;
                auto annoList = action->getAnnotations()->annotations;
                unsigned int tableFlag = PIL::TABLEDEFAULT;
                for (auto anno : annoList) {
                    if (anno->name == IR::Annotation::tableOnlyAnnotation) {
                        tableFlag = PIL::TABLEONLY;
                    }
                    if (anno->name == IR::Annotation::defaultOnlyAnnotation) {
                        tableFlag = PIL::DEFAULTONLY;
                    }
                }
                tableDefinition->addAction(actionDef, tableFlag);
            }
        }
        updateDefaultHitAction(t, tableDefinition);
        updateDefaultMissAction(t, tableDefinition);
        updateMatchType(t, tableDefinition);
        tcPipeline->addTableDefinition(tableDefinition);
    }
}

void ConvertToBackendIR::postorder(const IR::P4Program *p) {
    if (p != nullptr) {
        tcPipeline->setPipelineName(pipelineName);
        tcPipeline->setPipelineId(PIL::DEFAULT_PIPELINE_ID);
        tcPipeline->setNumTables(tableCount);
    }
}

/**
 * This function is used for checking whether given member is PNA Parser metadata
 */
bool ConvertToBackendIR::isPnaParserMeta(const IR::Member *mem) {
    if (mem->expr != nullptr && mem->expr->type != nullptr) {
        if (auto str_type = mem->expr->type->to<IR::Type_Struct>()) {
            if (str_type->name == pnaParserMeta) return true;
        }
    }
    return false;
}

bool ConvertToBackendIR::isPnaMainInputMeta(const IR::Member *mem) {
    if (mem->expr != nullptr && mem->expr->type != nullptr) {
        if (auto str_type = mem->expr->type->to<IR::Type_Struct>()) {
            if (str_type->name == pnaInputMeta) return true;
        }
    }
    return false;
}

bool ConvertToBackendIR::isPnaMainOutputMeta(const IR::Member *mem) {
    if (mem->expr != nullptr && mem->expr->type != nullptr) {
        if (auto str_type = mem->expr->type->to<IR::Type_Struct>()) {
            if (str_type->name == pnaOutputMeta) return true;
        }
    }
    return false;
}

unsigned int ConvertToBackendIR::findMappedKernelMeta(const IR::Member *mem) {
    if (isPnaParserMeta(mem)) {
        for (auto i = 0; i < PIL::MAX_PNA_PARSER_META; i++) {
            if (mem->member.name == pnaMainParserInputMetaFields[i]) {
                if (i == PIL::PARSER_RECIRCULATED) {
                    return PIL::SKBREDIR;
                } else if (i == PIL::PARSER_INPUT_PORT) {
                    return PIL::SKBIIF;
                }
            }
        }
    } else if (isPnaMainInputMeta(mem)) {
        for (auto i = 0; i < PIL::MAX_PNA_INPUT_META; i++) {
            if (mem->member.name == pnaMainInputMetaFields[i]) {
                switch (i) {
                    case PIL::INPUT_RECIRCULATED:
                        return PIL::SKBREDIR;
                    case PIL::INPUT_TIMESTAMP:
                        return PIL::SKBTSTAMP;
                    case PIL::INPUT_PARSER_ERROR:
                        ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                                "%1% is not supported in this target", mem);
                        return PIL::UNSUPPORTED;
                    case PIL::INPUT_CLASS_OF_SERVICE:
                        return PIL::SKBPRIO;
                    case PIL::INPUT_INPUT_PORT:
                        return PIL::SKBIIF;
                }
            }
        }
    } else if (isPnaMainOutputMeta(mem)) {
        if (mem->member.name == pnaMainOutputMetaFields[PIL::OUTPUT_CLASS_OF_SERVICE]) {
            return PIL::SKBPRIO;
        }
    }
    return PIL::UNDEFINED;
}

const IR::Expression *ConvertToBackendIR::ExtractExpFromCast(const IR::Expression *exp) {
    const IR::Expression *castexp = exp;
    while (castexp->is<IR::Cast>()) {
        castexp = castexp->to<IR::Cast>()->expr;
    }
    return castexp;
}

unsigned ConvertToBackendIR::getTcType(const IR::StringLiteral *sl) {
    auto value = sl->value;
    auto typeVal = PIL::BIT_TYPE;
    if (value == "dev") {
        typeVal = PIL::DEV_TYPE;
    } else if (value == "macaddr") {
        typeVal = PIL::MACADDR_TYPE;
    } else if (value == "ipv4") {
        typeVal = PIL::IPV4_TYPE;
    } else if (value == "ipv6") {
        typeVal = PIL::IPV6_TYPE;
    } else if (value == "be16") {
        typeVal = PIL::BE16_TYPE;
    } else if (value == "be32") {
        typeVal = PIL::BE32_TYPE;
    } else if (value == "be64") {
        typeVal = PIL::BE64_TYPE;
    }
    return typeVal;
}

unsigned ConvertToBackendIR::getTableId(cstring tableName) const {
    for (auto t : tableIDList) {
        if (t.second == tableName) return t.first;
    }
    return 0;
}

unsigned ConvertToBackendIR::getActionId(cstring actionName) const {
    for (auto a : actionIDList) {
        if (a.second == actionName) return a.first;
    }
    return 0;
}

unsigned ConvertToBackendIR::getTableKeysize(unsigned tableId) const {
    auto itr = tableKeysizeList.find(tableId);
    if (itr != tableKeysizeList.end()) return itr->second;
    return 0;
}

void ConvertToBackendIR::updateMatchType(const IR::P4Table *t, IR::PILTable *tabledef) {
    auto key = t->getKey();
    auto tableMatchType = PIL::EXACT_TYPE;
    if (key != nullptr && key->keyElements.size()) {
        if (key->keyElements.size() == 1) {
            auto matchTypeExp = key->keyElements[0]->matchType->path;
            auto mtdecl = refMap->getDeclaration(matchTypeExp, true);
            auto matchTypeInfo = mtdecl->getNode()->to<IR::Declaration_ID>();
            if (matchTypeInfo->name.name == P4::P4CoreLibrary::instance().exactMatch.name) {
                tableMatchType = PIL::EXACT_TYPE;
            } else if (matchTypeInfo->name.name == P4::P4CoreLibrary::instance().lpmMatch.name) {
                tableMatchType = PIL::LPM_TYPE;
            } else if (matchTypeInfo->name.name ==
                       P4::P4CoreLibrary::instance().ternaryMatch.name) {
                tableMatchType = PIL::TERNARY_TYPE;
            } else {
                ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                        "match type %1% is not supported in this target",
                        key->keyElements[0]->matchType);
                return;
            }
        } else {
            unsigned totalKey = key->keyElements.size();
            unsigned exactKey = 0;
            unsigned lpmKey = 0;
            unsigned ternaryKey = 0;
            unsigned keyCount = 0;
            unsigned lastkeyMatchType = PIL::EXACT_TYPE;
            unsigned keyMatchType;
            for (auto k : key->keyElements) {
                auto matchTypeExp = k->matchType->path;
                auto mtdecl = refMap->getDeclaration(matchTypeExp, true);
                auto matchTypeInfo = mtdecl->getNode()->to<IR::Declaration_ID>();
                if (matchTypeInfo->name.name == P4::P4CoreLibrary::instance().exactMatch.name) {
                    keyMatchType = PIL::EXACT_TYPE;
                    exactKey++;
                } else if (matchTypeInfo->name.name ==
                           P4::P4CoreLibrary::instance().lpmMatch.name) {
                    keyMatchType = PIL::LPM_TYPE;
                    lpmKey++;
                } else if (matchTypeInfo->name.name ==
                           P4::P4CoreLibrary::instance().ternaryMatch.name) {
                    keyMatchType = PIL::TERNARY_TYPE;
                    ternaryKey++;
                } else {
                    ::error(ErrorType::ERR_UNSUPPORTED_ON_TARGET,
                            "match type %1% is not supported in this target", k->matchType);
                    return;
                }
                keyCount++;
                if (keyCount == totalKey) {
                    lastkeyMatchType = keyMatchType;
                }
            }
            if (ternaryKey >= 1 || lpmKey > 1) {
                tableMatchType = PIL::TERNARY_TYPE;
            } else if (exactKey == totalKey) {
                tableMatchType = PIL::EXACT_TYPE;
            } else if (lpmKey == 1 && lastkeyMatchType == PIL::LPM_TYPE) {
                tableMatchType = PIL::LPM_TYPE;
            }
        }
    }
    tabledef->setMatchType(tableMatchType);
}

}  // namespace PIL
