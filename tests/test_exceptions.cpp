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
  
  
  Test("OutOfBounds").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    {
      llvm::Function* function = llvm_module->getFunction("out_of_bounds_1");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::OutOfBounds));
    }
    
    {
      hdl::Value* x = module.input("x", 32);
      llvm::Function* function = llvm_module->getFunction("out_of_bounds_2");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {x});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({x});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::OutOfBounds));
      unittest_assert(model.value().inputs.at(x).as_uint64() > 1);
    }
    
    {
      llvm::Function* function = llvm_module->getFunction("out_of_bounds_3");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::OutOfBounds));
    }
    
    {
      hdl::Value* x = module.input("x", 32);
      llvm::Function* function = llvm_module->getFunction("out_of_bounds_4");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {x});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({x});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::OutOfBounds));
      unittest_assert(model.value().inputs.at(x).as_uint64() == 10);
    }
    
    {
      hdl::Value* x = module.input("x", 32);
      llvm::Function* function = llvm_module->getFunction("out_of_bounds_5");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {x});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({x});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::OutOfBounds));
      unittest_assert(model.value().inputs.at(x).as_uint64() & (1 << 31));
    }
    
    {
      hdl::Value* x = module.input("x", 32);
      llvm::Function* function = llvm_module->getFunction("out_of_bounds_6");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {x});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({x});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::OutOfBounds));
      unittest_assert(model.value().inputs.at(x).as_uint64() == 3);
    }
    
    {
      llvm::Function* function = llvm_module->getFunction("no_out_of_bounds_1");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(!model.has_value());
    }
    
    {
      hdl::Value* x = module.input("x", 32);
      llvm::Function* function = llvm_module->getFunction("no_out_of_bounds_2");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {x});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({x});
      unittest_assert(!model.has_value());
    }
    
    {
      llvm::Function* function = llvm_module->getFunction("no_out_of_bounds_3");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(!model.has_value());
    }
  });
  
  Test("UseAfterFree").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    
    {
      llvm::Function* function = llvm_module->getFunction("use_after_free_1");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::UseAfterFree));
    }
    
    {
      hdl::Value* x = module.input("x", 32);
      llvm::Function* function = llvm_module->getFunction("use_after_free_2");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {x});
      //pathbeaver::Trace merged = initial_trace.trace_recursive();
      pathbeaver::Trace merged = pathbeaver::Trace::merge(initial_trace.trace()).value();
      
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({x});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::UseAfterFree));
      unittest_assert(model.value().inputs.at(x).as_uint64() == 1234567);
    }
    
    {
      llvm::Function* function = llvm_module->getFunction("no_use_after_free_1");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(!model.has_value());
    }
    
    {
      llvm::Function* function = llvm_module->getFunction("no_use_after_free_2");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(!model.has_value());
    }
  });
  
  Test("DoubleFree").run([&](){
    
  });
  
  Test("NullAccess").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    {
      llvm::Function* function = llvm_module->getFunction("null_access_1");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::NullAccess));
    }
    
    {
      llvm::Function* function = llvm_module->getFunction("null_access_2");
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(function, {});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      std::optional<pathbeaver::Exceptions::Model> model = merged.exceptions().prove({});
      unittest_assert(model.has_value());
      unittest_assert(model.value().triggers(pathbeaver::Exceptions::Kind::NullAccess));
    }
  });
  
  return 0;
}
