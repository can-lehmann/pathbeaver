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

hdl::Value* trace(hdl::Module& module,
                  pathbeaver::Globals& globals,
                  llvm::Function* function,
                  const std::vector<pathbeaver::Value>& args) {
  pathbeaver::Trace initial_trace(module, globals);
  initial_trace.call(function, args);
  pathbeaver::Trace merged = initial_trace.trace_recursive();
  std::set<hdl::Value*> inputs;
  for (const pathbeaver::Value& value : args) {
    inputs.insert(value.primitive());
  }
  merged.exceptions().ensure_none_occur(inputs);
  return merged.toplevel_return_value().primitive();
}

void assert_equivalent(hdl::Module& module,
                       const std::set<hdl::Value*>& inputs,
                       hdl::Value* a, hdl::Value* b) {
  z3::context context;
  z3::solver solver(context);
  hdl::proof::z3::Builder builder(context);
  
  for (hdl::Value* input : inputs) {
    builder.free(input);
  }
  
  builder.require(
    solver,
    module.op(hdl::Op::Kind::Eq, {a, b}),
    hdl::BitString::from_bool(false)
  );
  
  z3::check_result result = solver.check();
  if (result == z3::sat) {
    for (hdl::Value* input : inputs) {
      std::cout << builder.interp(solver, input) << ", " << builder.interp(solver, input).popcount() << std::endl;
    }
    std::cout << builder.interp(solver, a) << std::endl;
    std::cout << builder.interp(solver, b) << std::endl;
  }
  
  unittest_assert(result == z3::unsat);
}

int main(int argc, const char** argv) {
  if (argc != 2) {
    return 1;
  }
  
  llvm::LLVMContext llvm_context;
  llvm::SMDiagnostic error;
  std::unique_ptr<llvm::Module> llvm_module = llvm::parseIRFile(argv[1], error, llvm_context);
  
  Test("abs").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    hdl::Value* x = module.input("x", 64);
    
    hdl::Value* ret_a = trace(module, globals, llvm_module->getFunction("abs_1"), {x});
    hdl::Value* ret_b = trace(module, globals, llvm_module->getFunction("abs_2"), {x});
    
    assert_equivalent(module, {x}, ret_a, ret_b);
  });
  
  Test("parity").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    hdl::Value* x = module.input("x", 16);
    
    hdl::Value* ret_1 = trace(module, globals, llvm_module->getFunction("parity_1"), {x});
    hdl::Value* ret_2 = trace(module, globals, llvm_module->getFunction("parity_2"), {x});
    hdl::Value* ret_3 = trace(module, globals, llvm_module->getFunction("parity_3"), {x});
    
    assert_equivalent(module, {x}, ret_1, ret_2);
    assert_equivalent(module, {x}, ret_2, ret_3);
    assert_equivalent(module, {x}, ret_1, ret_3);
    
    hdl::Value* ret_4 = trace(module, globals, llvm_module->getFunction("parity_4"), {x});
    assert_equivalent(module, {x}, ret_1, ret_4);
    
    // TODO
    // hdl::Value* ret_5 = trace(module, globals, llvm_module->getFunction("parity_5"), {x});
    // assert_equivalent(module, {x}, ret_1, ret_5);
    
  });
  
  Test("popcount").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    hdl::Value* x = module.input("x", 16);
    
    hdl::Value* ret_1 = trace(module, globals, llvm_module->getFunction("popcount_1"), {x});
    hdl::Value* ret_2 = trace(module, globals, llvm_module->getFunction("popcount_2"), {x});
    hdl::Value* ret_3 = trace(module, globals, llvm_module->getFunction("popcount_3"), {x});
    
    assert_equivalent(module, {x}, ret_1, ret_2);
    assert_equivalent(module, {x}, ret_2, ret_3);
    assert_equivalent(module, {x}, ret_1, ret_3);
  });
  
  Test("swap").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    hdl::Unknown* a = globals.initial_memory().alloc(module.constant(hdl::BitString::from_uint(uint64_t(4))));
    hdl::Unknown* b = globals.initial_memory().alloc(module.constant(hdl::BitString::from_uint(uint64_t(4))));
    
    std::set<hdl::Value*> inputs;
    for (hdl::Value* byte : globals.initial_memory().load_bytes(a)) {
      inputs.insert(byte);
    }
    for (hdl::Value* byte : globals.initial_memory().load_bytes(b)) {
      inputs.insert(byte);
    }
    
    hdl::Value* res_1 = nullptr;
    hdl::Value* res_2 = nullptr;
    
    {
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(llvm_module->getFunction("swap_1"), {a, b});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      merged.exceptions().ensure_none_occur(inputs);
      
      res_1 = module.op(hdl::Op::Kind::Concat, {
        merged.memory().load_all(a),
        merged.memory().load_all(b)
      });
    }
    
    {
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(llvm_module->getFunction("swap_2"), {a, b});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      merged.exceptions().ensure_none_occur(inputs);
      
      res_2 = module.op(hdl::Op::Kind::Concat, {
        merged.memory().load_all(a),
        merged.memory().load_all(b)
      });
    }
    
    assert_equivalent(module, inputs, res_1, res_2);
  });
  
  
  Test("sum").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    hdl::Value* size = module.constant(hdl::BitString::from_uint(uint32_t(10)));
    hdl::Unknown* values = globals.initial_memory().alloc(module.constant(hdl::BitString::from_uint(uint64_t(10 * 4))));
    
    std::set<hdl::Value*> inputs;
    for (hdl::Value* byte : globals.initial_memory().load_bytes(values)) {
      inputs.insert(byte);
    }
    
    hdl::Value* ret_1 = trace(module, globals, llvm_module->getFunction("sum_1"), {values, size});
    hdl::Value* ret_2 = trace(module, globals, llvm_module->getFunction("sum_2"), {values, size});
    // TODO: hdl::Value* ret_3 = trace(module, globals, llvm_module->getFunction("sum_3"), {values, size});
    
    assert_equivalent(module, inputs, ret_1, ret_2);
    // TODO: assert_equivalent(module, inputs, ret_1, ret_3);
    // TODO: assert_equivalent(module, inputs, ret_2, ret_3);
  });
  
  Test("sort").run([&](){
    hdl::Module module("top");
    pathbeaver::Globals globals(module, &*llvm_module);
    
    hdl::Value* size = module.constant(hdl::BitString::from_uint(uint32_t(5)));
    hdl::Unknown* values = globals.initial_memory().alloc(module.constant(hdl::BitString::from_uint(uint64_t(5 * 4))));
    
    std::set<hdl::Value*> inputs;
    for (hdl::Value* byte : globals.initial_memory().load_bytes(values)) {
      inputs.insert(byte);
    }
    
    hdl::Value* is_sorted_1 = nullptr;
    {
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(llvm_module->getFunction("sort_1_is_sorted"), {values, size});
      pathbeaver::Trace merged = initial_trace.trace_recursive();
      merged.exceptions().ensure_none_occur(inputs);
      is_sorted_1 = merged.toplevel_return_value().primitive();
    }
    assert_equivalent(module, inputs, is_sorted_1, module.constant(hdl::BitString::from_bool(true)));
    
    hdl::Value* is_sorted_2 = nullptr;
    {
      pathbeaver::Trace initial_trace(module, globals);
      initial_trace.call(llvm_module->getFunction("sort_2_is_sorted"), {values, size});
      pathbeaver::Trace merged = pathbeaver::Trace::merge(initial_trace.trace()).value(); // TODO
      merged.exceptions().ensure_none_occur(inputs);
      is_sorted_2 = merged.toplevel_return_value().primitive();
    }
    assert_equivalent(module, inputs, is_sorted_2, module.constant(hdl::BitString::from_bool(true)));
    
  });
  
  return 0;
}
