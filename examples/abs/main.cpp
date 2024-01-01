// Copyright 2023 Can Joshua Lehmann
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>
#include <memory>

#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>

#include <z3++.h>

#include "../../src/pathbeaver.hpp"

#include "../../modules/hdl.cpp/hdl_proof.hpp"
#include "../../modules/hdl.cpp/hdl_proof_z3.hpp"
#include "../../modules/hdl.cpp/hdl_flatten.hpp"

int main(int argc, const char** argv) {
  if (argc != 2) {
    std::cerr << "Usage:\n\t" << argv[0] << " <llvm_ir.bc>" << std::endl;
    return 1;
  }
  
  llvm::LLVMContext llvm_context;
  llvm::SMDiagnostic error;
  std::unique_ptr<llvm::Module> llvm_module = llvm::parseIRFile(argv[1], error, llvm_context);
  
  hdl::Module module("top");
  pathbeaver::Globals globals(module, &*llvm_module);
  
  hdl::Value* x = module.input("x", 64);
  
  pathbeaver::Trace trace(module, globals);
  pathbeaver::Value ret_a = trace.trace_simple(llvm_module->getFunction("abs_1"), {x});
  pathbeaver::Value ret_b = trace.trace_simple(llvm_module->getFunction("abs_2"), {x});
  
  z3::context context;
  z3::solver solver(context);
  hdl::proof::z3::Builder builder(context);
  
  builder.free(x);
  builder.require(
    solver,
    module.op(hdl::Op::Kind::Eq, {
      ret_a.primitive(), ret_b.primitive()
    }),
    hdl::BitString::from_bool(false)
  );
  
  std::cout << solver.check() << std::endl;
  
  return 0;
}
