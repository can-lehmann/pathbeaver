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

#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>

#include "../src/pathbeaver.hpp"

#undef assert
#include "../modules/unittest.cpp/unittest.hpp"

using Test = unittest::Test;

int main(int argc, const char** argv) {
  if (argc != 2) {
    return 1;
  }
  
  llvm::LLVMContext llvm_context;
  llvm::SMDiagnostic error;
  std::unique_ptr<llvm::Module> llvm_module = llvm::parseIRFile(argv[1], error, llvm_context);
  
  if (!llvm_module) {
    error.print(argv[1], llvm::outs());
    return 1;
  }
  
  llvm::ExecutionEngine* engine = llvm::EngineBuilder(llvm::CloneModule(*llvm_module))
    .setEngineKind(llvm::EngineKind::Interpreter)
    .create();
  
  for (llvm::Function& function : llvm_module->functions()) {
    if (function.getName().starts_with("llvm")) {
      continue;
    }
    
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    pathbeaver::Trace trace(module, globals);
    
    Test(function.getName().str().c_str()).repeat(10).run([&](){
      std::vector<pathbeaver::Value> pathbeaver_args;
      std::vector<llvm::GenericValue> llvm_args;
      for (llvm::Argument& arg : function.args()) {
        hdl::BitString value = hdl::BitString::random(arg.getType()->getPrimitiveSizeInBits());
        pathbeaver_args.emplace_back(module.constant(value));
        llvm::GenericValue generic_value;
        generic_value.IntVal = pathbeaver::bit_string_to_ap_int(value);
        llvm_args.push_back(generic_value);
      }
      
      llvm::GenericValue expected = engine->runFunction(&function, llvm_args);
      pathbeaver::Value ret = trace.trace_simple(&function, pathbeaver_args);
      
      hdl::Constant* const_ret = dynamic_cast<hdl::Constant*>(ret.primitive());
      unittest_assert(const_ret != nullptr);
      
      bool eq = const_ret->value == pathbeaver::ap_int_to_bit_string(expected.IntVal);
      if (!eq) {
        std::cout << "Return: " << const_ret->value << std::endl;
        std::cout << "Expected: " << pathbeaver::ap_int_to_bit_string(expected.IntVal) << std::endl;
        unittest_assert(false);
      }
    });
  }
  
  return 0;
}
