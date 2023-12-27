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

#ifndef PATHBEAVER_HPP
#define PATHBEAVER_HPP

#include <vector>
#include <map>
#include <stdexcept>
#include <sstream>
#include <variant>
#include <deque>
#include <optional>

#include <inttypes.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Constants.h>

#include <llvm/Analysis/PostDominators.h>

#include <z3++.h>

#include "../modules/hdl.cpp/hdl.hpp"
#include "../modules/hdl.cpp/hdl_analysis.hpp"
#include "../modules/hdl.cpp/hdl_proof_z3.hpp"

#define throw_error(Error, msg) {\
  std::ostringstream message_stream; \
  message_stream << msg; \
  throw Error(message_stream.str()); \
}

#define llvm_match(Type, into, value) llvm::Type* into = llvm::dyn_cast<llvm::Type>(value)

namespace pathbeaver {
  template <class T>
  inline void move_into(T& into, T&& value) {
    into.~T();
    new(&into) T(std::move(value));
  }
  
  inline hdl::BitString ap_int_to_bit_string(const llvm::APInt& ap_int) {
    hdl::BitString bit_string(ap_int.getBitWidth());
    for (size_t it = 0; it < bit_string.width(); it++) {
      bit_string.set(it, ap_int[it]);
    }
    return bit_string;
  }

  class Error: public std::runtime_error {
    using std::runtime_error::runtime_error;
  };
  
  class Value {
  public:
    enum class Kind {
      Primitive, Array
    };
    
    struct Array: public std::vector<Value> {
      using std::vector<Value>::vector;
    };
  private:
    std::variant<hdl::Value*, Array> _value;
  public:
    Value(hdl::Value* value): _value(value) {}
    Value(const Array& value): _value(value) {}
    
  private:
    static hdl::Value* prop_concat(hdl::Value* high, hdl::Value* low, hdl::Module& module) {
      hdl::Op* high_op = dynamic_cast<hdl::Op*>(high);
      hdl::Op* low_op = dynamic_cast<hdl::Op*>(low);
      if (high_op &&
          low_op &&
          high_op->kind == hdl::Op::Kind::Select &&
          low_op->kind == hdl::Op::Kind::Select &&
          low_op->args[0] == high_op->args[0]) {
        return module.op(hdl::Op::Kind::Select, {
          low_op->args[0],
          prop_concat(high_op->args[1], low_op->args[1], module),
          prop_concat(high_op->args[2], low_op->args[2], module)
        });
      }
      return module.op(hdl::Op::Kind::Concat, {high, low});
    }
    
  public:
    static Value from_bytes(llvm::Type* type,
                            const llvm::DataLayout& data_layout,
                            const std::vector<hdl::Value*>& bytes,
                            hdl::Module& module) {
      size_t size = data_layout.getTypeStoreSize(type);
      hdl::Value* value = nullptr;
      for (size_t offset = 0; offset < size; offset++) {
        hdl::Value* byte = bytes[offset];
        
        if (value == nullptr) {
          value = byte;
        } else {
          if (data_layout.isLittleEndian()) {
            value = prop_concat(byte, value, module);
          } else {
            value = prop_concat(value, byte, module);
          }
        }
      }
      if (llvm_match(IntegerType, integer_type, type)) {
        size_t bit_width = integer_type->getBitWidth();
        if (bit_width != value->width) {
          value = module.op(hdl::Op::Kind::Slice, {
            value,
            module.constant(hdl::BitString::from_uint(0)),
            module.constant(hdl::BitString::from_uint(bit_width))
          });
        }
      }
      return Value(value);
    }
    
    Kind kind() const { return Kind(_value.index()); }
    hdl::Value* primitive() const { return std::get<hdl::Value*>(_value); }
    const Array& array() const { return std::get<Array>(_value); }
    
    std::map<size_t, hdl::Value*> to_bytes(llvm::Type* type,
                                           const llvm::DataLayout& data_layout,
                                           hdl::Module& module) const {
      std::map<size_t, hdl::Value*> layout;
      to_bytes(type, layout, 0, data_layout, module);
      return layout;
    }
    
    void to_bytes(llvm::Type* type,
                  std::map<size_t, hdl::Value*>& layout,
                  size_t offset,
                  const llvm::DataLayout& data_layout,
                  hdl::Module& module) const {
      switch (kind()) {
        case Kind::Primitive: {
          size_t size = data_layout.getTypeStoreSize(type);
          hdl::Value* value = primitive();
          if (value->width % 8 != 0) {
            value = module.op(hdl::Op::Kind::Concat, {
              module.constant(hdl::BitString(8 - (value->width % 8))),
              value
            });
          }
          for (size_t it = 0; it < size; it++) {
            hdl::Value* byte = module.op(hdl::Op::Kind::Slice, {
              value,
              module.constant(hdl::BitString::from_uint(it * 8)),
              module.constant(hdl::BitString::from_uint(8))
            });
            if (data_layout.isLittleEndian()) {
              layout.insert({offset + it, byte});
            } else {
              layout.insert({offset + (size - it - 1), byte});
            }
          }
        }
        break;
        case Kind::Array: {
          llvm_match(ArrayType, array_type, type);
          size_t size = data_layout.getTypeAllocSize(array_type->getElementType());
          for (size_t it = 0; it < array().size(); it++) {
            array()[it].to_bytes(
              array_type->getElementType(),
              layout,
              offset + it * size,
              data_layout,
              module
            );
          }
        }
        break;
        default:
          throw_error(Error, "Not implemented");
        break;
      }
    }
  };
  
  class Exceptions {
  public:
    enum class Kind {
      None,
      OutOfBounds,
      UseAfterFree,
      DoubleFree,
      NullAccess
    };
    
    static constexpr const char* KIND_NAMES[] = {
      "None",
      "OutOfBounds",
      "UseAfterFree",
      "DoubleFree",
      "NullAccess"
    };
    
    struct Exception {
      Kind kind = Kind::None;
      hdl::Value* condition = nullptr;
      llvm::Instruction* source = nullptr;
      
      Exception() {}
      Exception(Kind _kind, hdl::Value* _condition, llvm::Instruction* _source):
        kind(_kind), condition(_condition), source(_source) {}
      
      Exception with_requirement(hdl::Value* cond, hdl::Module& module) const {
        Exception exception = *this;
        exception.condition = module.op(hdl::Op::Kind::And, {exception.condition, cond});
        return exception;
      }
    };
    
    struct Model {
      std::map<hdl::Value*, hdl::BitString> inputs;
      std::vector<Exception> triggered;
      
      bool triggers(Kind kind) const {
        for (const Exception& exception : triggered) {
          if (exception.kind == kind) {
            return true;
          }
        }
        return false;
      }
    };
  private:
    hdl::Module& _module;
    llvm::Instruction* _current_source = nullptr;
    std::vector<Exception> _exceptions;
  public:
    Exceptions(hdl::Module& module): _module(module) {}
    
    inline size_t size() const { return _exceptions.size(); }
    inline llvm::Instruction* current_source() const { return _current_source; }
    
    void set_current_source(llvm::Instruction* source) { 
      _current_source = source;
    }
    
    void add(const Exception& exception) {
      if (hdl::Constant* constant = dynamic_cast<hdl::Constant*>(exception.condition)) {
        if (constant->value.is_zero()) {
          return;
        }
      }
      _exceptions.push_back(exception);
    }
    
    void add(Kind kind, hdl::Value* condition) {
      add(Exception(kind, condition, _current_source));
    }
    
    void add(Kind kind) {
      add(kind, _module.constant(hdl::BitString::from_bool(true)));
    }
    
    void merge_inplace(const Exceptions& other, hdl::Value* cond) {
      for (Exception& exception : _exceptions) {
        exception = exception.with_requirement(cond, _module);
      }
      
      hdl::Value* not_cond = _module.op(hdl::Op::Kind::Not, {cond});
      for (const Exception& exception : other._exceptions) {
        _exceptions.push_back(exception.with_requirement(not_cond, _module));
      }
    }
    
    hdl::Value* any_occurred() const {
      hdl::Value* result = _module.constant(hdl::BitString::from_bool(false));
      for (const Exception& exception : _exceptions) {
        result = _module.op(hdl::Op::Kind::Or, {
          result,
          exception.condition
        });
      }
      return result;
    }
    
    std::optional<Model> prove(const std::set<hdl::Value*> inputs) const {
      z3::context context;
      z3::solver solver(context);
      hdl::proof::z3::Builder builder(context);
      
      for (hdl::Value* input : inputs) {
        builder.free(input);
      }
      
      builder.require(
        solver,
        any_occurred(),
        hdl::BitString::from_bool(true)
      );
      
      z3::check_result result = solver.check();
      if (result == z3::sat) {
        Model model;
        for (hdl::Value* input : inputs) {
          model.inputs[input] = builder.interp(solver, input);
        }
        
        for (const Exception& exception : _exceptions) {
          if (builder.interp(solver, exception.condition).is_all_ones()) {
            model.triggered.push_back(exception);
          }
        }
        
        return model;
      }
      
      return {};
    }
    
    void ensure_none_occur(const std::set<hdl::Value*>& inputs) const {
      std::optional<Model> model = prove(inputs);
      if (model.has_value()) {
        throw_error(Error, KIND_NAMES[size_t(model.value().triggered[0].kind)] << " exception occurred");
      }
    }
  };
  
  using AffineValue = hdl::analysis::AffineValue;
  
  class Memory {
  public:
    struct Write {
      hdl::Value* enable = nullptr;
      AffineValue offset = nullptr;
      hdl::Value* value = nullptr;
      
      Write(hdl::Value* _enable, AffineValue _offset, hdl::Value* _value):
        enable(_enable), offset(_offset), value(_value) {}
    };
    
    struct Chunk {
      hdl::Module* module = nullptr;
      hdl::Unknown* address = nullptr;
      hdl::Value* size = nullptr;
      
      std::map<uint64_t, hdl::Value*> base;
      std::vector<Write> writes;
      
      Chunk(hdl::Module* _module, hdl::Unknown* _address, hdl::Value* _size):
        module(_module), address(_address), size(_size) {}
      
      void store(hdl::Value* enable, const AffineValue& offset, hdl::Value* value, Exceptions* exceptions) {
        if (exceptions != nullptr) {
          exceptions->add(
            Exceptions::Kind::OutOfBounds,
            module->op(hdl::Op::Kind::And, {
              enable,
              module->op(hdl::Op::Kind::Not, {
                module->op(hdl::Op::Kind::LtU, {offset.build(*module), size})
              })
            })
          );
        }
        
        if (offset.is_constant()) {
          if (base.find(offset.constant.as_uint64()) == base.end()) {
            base[offset.constant.as_uint64()] = module->unknown(8);
          }
          base[offset.constant.as_uint64()] = module->op(hdl::Op::Kind::Select, {
            enable, value, base.at(offset.constant.as_uint64())
          });
        } else {
          throw_error(Error, "");
          writes.emplace_back(enable, offset, value);
        }
      }
      
      void store(const AffineValue& offset, hdl::Value* value, Exceptions* exceptions) {
        store(module->constant(hdl::BitString::from_bool(true)), offset, value, exceptions);
      }
      
      hdl::Value* load(const AffineValue& offset, Exceptions* exceptions) {
        if (exceptions != nullptr) {
          exceptions->add(
            Exceptions::Kind::OutOfBounds,
            module->op(hdl::Op::Kind::Not, {
              module->op(hdl::Op::Kind::LtU, {offset.build(*module), size})
            })
          );
        }
        
        if (offset.is_constant()) {
          if (base.find(offset.constant.as_uint64()) == base.end()) {
            base[offset.constant.as_uint64()] = module->unknown(8);
          }
          return base.at(offset.constant.as_uint64());
        } else {
          throw_error(Error, "");
          
          hdl::Value* result = module->unknown(8);
          for (const Write& write : writes) {
            result = module->op(hdl::Op::Kind::Select, {
              module->op(hdl::Op::Kind::And, {
                write.enable,
                module->op(hdl::Op::Kind::Eq, {
                  (offset - write.offset).build(*module),
                  module->constant(hdl::BitString(offset.width()))
                })
              }),
              write.value,
              result
            });
          }
          return result;
        }
      }
      
      bool merge_inplace(const Chunk& other_chunk, hdl::Value* cond) {
        if (size != other_chunk.size) {
          return false;
        }
        
        hdl::Value* not_cond = module->op(hdl::Op::Kind::Not, {cond});
        for (const auto& [offset, value] : other_chunk.base) {
          store(not_cond, AffineValue(hdl::BitString::from_uint(offset).truncate(address->width)), value, nullptr);
        }
        
        /*for (const Write& write : other_chunk.writes) {
          hdl::Value* enable = module->op(hdl::Op::Kind::And, {write.enable, not_cond});
          store(enable, write.offset, write.value);
        }*/
        
        return true;
      }
    };
  private:
    hdl::Module* _module = nullptr;
    // Deallocated chunks remain in the map, but are assigned std::optional<Chunk>()
    std::map<hdl::Unknown*, std::optional<Chunk>> _chunks;
  public:
    Memory(hdl::Module* module): _module(module) {}
    
    std::optional<Chunk>& operator[](hdl::Unknown* base_address) { return _chunks.at(base_address); }
    const std::optional<Chunk>& operator[](hdl::Unknown* base_address) const { return _chunks.at(base_address); }
    
    hdl::Unknown* alloc(hdl::Value* size) {
      hdl::Unknown* base_address = _module->unknown(size->width);
      _chunks.insert({base_address, Chunk(_module, base_address, size)});
      return base_address;
    }
    
    void dealloc(hdl::Unknown* base_address) {
      _chunks[base_address] = std::optional<Chunk>();
    }
    
    struct BaseOffset {
      hdl::Unknown* base = nullptr;
      AffineValue offset;
      
      BaseOffset(hdl::Unknown* _base, const AffineValue& _offset):
        base(_base), offset(_offset) {}
    };
    
    std::optional<BaseOffset> split_address(hdl::Value* address) {
      AffineValue affine = AffineValue::build(address);
      for (const auto& [value, factor] : affine.factors) {
        if (hdl::Unknown* base = dynamic_cast<hdl::Unknown*>(value)) {
          if (factor.as_uint64() == 1 && _chunks.find(base) != _chunks.end()) {
            return BaseOffset(base, affine - AffineValue(base));
          }
        }
      }
      return {};
    }
    
    hdl::Value* load(hdl::Value* address, Exceptions* exceptions) {
      std::optional<BaseOffset> split = split_address(address);
      if (!split.has_value()) {
        if (exceptions != nullptr && dynamic_cast<hdl::Constant*>(address)) {
          exceptions->add(Exceptions::Kind::NullAccess);
          return _module->unknown(8);
        }
        throw_error(Error, "TODO");
      }
      std::optional<Chunk>& chunk = _chunks.at(split.value().base);
      if (exceptions != nullptr && !chunk.has_value()) {
        exceptions->add(Exceptions::Kind::UseAfterFree);
        return _module->unknown(8);
      }
      return chunk.value().load(split.value().offset, exceptions);
    }
    
    void store(hdl::Value* address, hdl::Value* value, Exceptions* exceptions) {
      if (value->width != 8) {
        throw_error(Error, "");
      }
      std::optional<BaseOffset> split = split_address(address);
      if (!split.has_value()) {
        if (exceptions != nullptr && dynamic_cast<hdl::Constant*>(address)) {
          exceptions->add(Exceptions::Kind::NullAccess);
          return;
        }
        throw_error(Error, "TODO");
      }
      std::optional<Chunk>& chunk = _chunks.at(split.value().base);
      if (exceptions != nullptr && !chunk.has_value()) {
        exceptions->add(Exceptions::Kind::UseAfterFree);
        return;
      }
      chunk.value().store(split.value().offset, value, exceptions);
    }
    
    std::vector<hdl::Value*> load_bytes(hdl::Unknown* base_address) {
      Chunk& chunk = _chunks.at(base_address).value();
      if (hdl::Constant* constant_size = dynamic_cast<hdl::Constant*>(chunk.size)) {
        size_t size = constant_size->value.as_uint64();
        std::vector<hdl::Value*> bytes;
        bytes.reserve(size);
        for (size_t it = 0; it < size; it++) {
          AffineValue offset(hdl::BitString::from_uint(it).truncate(base_address->width));
          hdl::Value* byte = chunk.load(offset, nullptr);
          bytes.push_back(byte);
        }
        return bytes;
      } else {
        throw_error(Error, "Chunk must have constant size");
      }
    }
    
    hdl::Value* load_all(hdl::Unknown* base_address) {
      std::vector<hdl::Value*> bytes = load_bytes(base_address);
      
      hdl::Value* result = nullptr;
      for (hdl::Value* byte : bytes) {
        if (result == nullptr) {
          result = byte;
        } else {
          result = _module->op(hdl::Op::Kind::Concat, {result, byte});
        }
      }
      return result;
    }
    
    bool merge_inplace(const Memory& other, hdl::Value* cond) {
      for (const auto& [base_address, chunk] : other._chunks) {
        if (_chunks.find(base_address) == _chunks.end()) {
          _chunks.insert({base_address, chunk});
        } else if (_chunks.at(base_address).has_value() != chunk.has_value()) {
          return false;
        } else if (chunk.has_value()) {
          if (!_chunks.at(base_address).value().merge_inplace(chunk.value(), cond)) {
            return false;
          }
        }
      }
      
      return true;
    }
  };
  
  class Globals {
  private:
    hdl::Module& _module;
    llvm::Module* _llvm_module = nullptr;
    Memory _initial_memory;
    std::map<llvm::GlobalVariable*, hdl::Unknown*> _variables;
    std::map<llvm::Function*, hdl::Unknown*> _functions;
    std::map<hdl::Unknown*, llvm::Function*> _unknown_to_function;
  public:
    Globals(hdl::Module& module, llvm::Module* llvm_module):
        _module(module),
        _llvm_module(llvm_module),
        _initial_memory(&module) {
      
      const llvm::DataLayout& data_layout = _llvm_module->getDataLayout();
      size_t pointer_width = data_layout.getPointerSizeInBits();
      
      for (llvm::GlobalVariable& global_variable : _llvm_module->globals()) {
        llvm::Constant* initializer = global_variable.getInitializer();
        size_t size = data_layout.getTypeAllocSize(initializer->getType());
        
        hdl::Value* size_value = _module.constant(hdl::BitString::from_uint(size).truncate(pointer_width));
        hdl::Unknown* base_address = _initial_memory.alloc(size_value);
        
        _variables[&global_variable] = base_address;
      }
      
      for (llvm::GlobalVariable& global_variable : _llvm_module->globals()) {
        hdl::Unknown* base_address = _variables.at(&global_variable);
        llvm::Constant* initializer = global_variable.getInitializer();
        
        Value initial_value = (*this)[initializer];
        std::map<size_t, hdl::Value*> layout = initial_value.to_bytes(
          initializer->getType(), data_layout, _module
        );
        
        for (const auto& [offset, byte] : layout) {
          hdl::Value* offset_value = _module.constant(
            hdl::BitString::from_uint(offset).truncate(pointer_width)
          );
          _initial_memory.store(
            _module.op(hdl::Op::Kind::Add, {base_address, offset_value}),
            byte,
            nullptr
          );
        }
      }
    }
    
    Memory& initial_memory() { return _initial_memory; }
    const Memory& initial_memory() const { return _initial_memory; }
    
    llvm::Function* function(hdl::Unknown* unknown) {
      return _unknown_to_function.at(unknown);
    }
    
    Value operator[](llvm::Constant* constant) {
      if (llvm_match(ConstantInt, constant_int, constant)) {
        return _module.constant(ap_int_to_bit_string(constant_int->getValue()));
      } else if (llvm_match(ConstantPointerNull, pointer_null, constant)) {
        const llvm::DataLayout& data_layout = _llvm_module->getDataLayout();
        size_t pointer_width = data_layout.getPointerSizeInBits();
        return _module.constant(hdl::BitString(pointer_width));
      } else if (llvm_match(ConstantDataArray, constant_data_array, constant)) {
        Value::Array array;
        array.reserve(constant_data_array->getNumElements());
        for (size_t it = 0; it < constant_data_array->getNumElements(); it++) {
          array.push_back((*this)[constant_data_array->getElementAsConstant(it)]);
        }
        return array;
      } else if (llvm_match(GlobalVariable, global_variable, constant)) {
        return _variables.at(global_variable);
      } else if (llvm_match(Function, function, constant)) {
        if (_functions.find(function) == _functions.end()) {
          const llvm::DataLayout& data_layout = _llvm_module->getDataLayout();
          size_t pointer_width = data_layout.getPointerSizeInBits();
          hdl::Unknown* unknown = _module.unknown(pointer_width);
          _functions.insert({function, unknown});
          _unknown_to_function.insert({unknown, function});
        }
        return _functions.at(function);
      } else {
        constant->print(llvm::outs());
        llvm::outs() << '\n';
        throw_error(Error, "Unknown constant");
      }
    }
  };
  
  class Trace {
  public:
    struct StackFrame {
      hdl::Module& module;
      Globals& globals;
      llvm::Instruction* pc = nullptr;
      std::vector<llvm::BasicBlock*> joins;
      std::unordered_map<llvm::Value*, Value> values;
      std::vector<hdl::Unknown*> allocations;
      
      StackFrame(hdl::Module& _module, Globals& _globals):
        module(_module), globals(_globals) {}
      
      Value operator[](llvm::Value* value) const {
        if (llvm_match(Constant, constant, value)) {
          return globals[constant];
        } else {
          return values.at(value);
        }
      }
      
      void set(llvm::Value* llvm_value, const Value& value) {
        values.insert_or_assign(llvm_value, value);
      }
      
      void next() {
        pc = pc->getNextNonDebugInstruction();
      }
      
      bool is_join(llvm::BasicBlock* block) {
        return joins.size() > 0 && joins.back() == block;
      }
    };
    
    struct Requirements {
      hdl::Module* module = nullptr;
      std::set<hdl::Value*> conditions;
      
      Requirements(hdl::Module* _module): module(_module) {}
      
      bool require(hdl::Value* value) {
        if (hdl::Constant* constant = dynamic_cast<hdl::Constant*>(value)) {
          return !constant->value.is_zero();
        }
        
        hdl::Value* not_value = module->op(hdl::Op::Kind::Not, {value});
        if (conditions.find(not_value) != conditions.end()) {
          return false;
        }
        conditions.insert(value);
        return true;
      }
      
      bool require_not(hdl::Value* value) {
        return require(module->op(hdl::Op::Kind::Not, {value}));
      }
      
      Requirements difference(const Requirements& other) const {
        Requirements result = *this;
        for (hdl::Value* value : other.conditions) {
          result.conditions.erase(value);
        }
        return result;
      }
      
      Requirements merge(const Requirements& other) {
        Requirements result(module);
        for (hdl::Value* value : conditions) {
          if (other.conditions.find(value) != other.conditions.end()) {
            result.conditions.insert(value);
          }
        }
        result.conditions.insert(module->op(hdl::Op::Kind::Or, {
          this->difference(other).build(),
          other.difference(*this).build()
        }));
        return result;
      }
      
      hdl::Value* build() const {
        hdl::Value* result = module->constant(hdl::BitString::from_bool(true));
        for (hdl::Value* cond : conditions) {
          result = module->op(hdl::Op::Kind::And, {result, cond});
        }
        return result;
      }
    };
    
  private:
    hdl::Module& _module;
    Globals& _globals;
    Requirements _requirements;
    Exceptions _exceptions;
    std::vector<StackFrame> _stack;
    Memory _memory;
  public:
    Trace(hdl::Module& module, Globals& globals):
      _module(module),
      _globals(globals),
      _requirements(&module),
      _exceptions(module),
      _memory(globals.initial_memory()) {}
    
    static std::optional<Trace> merge(const std::vector<Trace>& traces) {
      if (traces.size() == 0) {
        throw_error(Error, "");
      }
      
      Trace trace = traces.back();
      if (traces.size() > 1) {
        for (size_t it = traces.size() - 1; it-- > 0; ) {
          if (!trace.merge_inplace(traces[it])) {
            return {};
          }
        }
      }
      return trace;
    }
    
    hdl::Module& module() const { return _module; }
    const Requirements& requirements() const { return _requirements; }
    const Exceptions& exceptions() const { return _exceptions; }
    const std::vector<StackFrame>& stack() const { return _stack; }
    Memory& memory() { return _memory; }
    const Memory& memory() const { return _memory; }
    
    llvm::Instruction* current_inst() const { return _stack.back().pc; }
    
    Value toplevel_return_value() const {
      if (_stack.size() != 1 || _stack[0].pc != nullptr) {
        throw_error(Error, "Trace is not a toplevel return trace");
      }
      return _stack[0].values.at(nullptr);
    }
    
    void call(llvm::Function* function, const std::vector<Value> args) {
      if (args.size() != function->arg_size()) {
        throw_error(Error,
          "Function " << function->getName().str() << " expected " <<
          function->arg_size() << " arguments, but got " << args.size()
        );
      }
      
      StackFrame frame(_module, _globals);
      frame.pc = function->getEntryBlock().getFirstNonPHIOrDbg();
      for (size_t it = 0; it < args.size(); it++) {
        frame.values.insert({function->getArg(it), args[it]});
      }
      _stack.push_back(frame);
    }
    
    
    void enter(llvm::BasicBlock* block, llvm::BasicBlock* from) {
      StackFrame& frame = _stack.back();
      frame.pc = block->getFirstNonPHIOrDbg();
      std::vector<std::pair<llvm::Value*, Value>> assignments;
      for (llvm::PHINode& phi : block->phis()) {
        assignments.emplace_back(&phi, frame[phi.getIncomingValueForBlock(from)]);
      }
      for (const auto& [phi, value] : assignments) {
        frame.set(phi, value);
      }
    }
    
    hdl::Value* trace_binop(unsigned opcode, hdl::Value* a, hdl::Value* b) {
      switch (opcode) {
        case llvm::Instruction::Add: return _module.op(hdl::Op::Kind::Add, {a, b}); break;
        case llvm::Instruction::Sub: return _module.op(hdl::Op::Kind::Sub, {a, b}); break;
        case llvm::Instruction::And: return _module.op(hdl::Op::Kind::And, {a, b}); break;
        case llvm::Instruction::Or: return _module.op(hdl::Op::Kind::Or, {a, b}); break;
        case llvm::Instruction::Xor: return _module.op(hdl::Op::Kind::Xor, {a, b}); break;
        case llvm::Instruction::LShr: return _module.op(hdl::Op::Kind::ShrU, {a, b}); break;
        case llvm::Instruction::AShr: return _module.op(hdl::Op::Kind::ShrS, {a, b}); break;
        case llvm::Instruction::Shl: return _module.op(hdl::Op::Kind::Shl, {a, b}); break;
        default:
          throw_error(Error, "Binary Operator " << llvm::Instruction::getOpcodeName(opcode) << " is not implemented");
      }
    }
    
    void trace_binop(llvm::BinaryOperator* binop) {
      StackFrame& frame = _stack.back();
      Value a = frame[binop->getOperand(0)];
      Value b = frame[binop->getOperand(1)];
      hdl::Value* result = trace_binop(binop->getOpcode(), a.primitive(), b.primitive());
      frame.set(binop, Value(result));
    }
    
    hdl::Value* trace_cmp(llvm::CmpInst::Predicate predicate, hdl::Value* a, hdl::Value* b) {
      switch (predicate) {
        case llvm::CmpInst::ICMP_EQ: return _module.op(hdl::Op::Kind::Eq, {a, b}); break;
        case llvm::CmpInst::ICMP_NE: return _module.op(hdl::Op::Kind::Not, {_module.op(hdl::Op::Kind::Eq, {a, b})}); break;
        case llvm::CmpInst::ICMP_UGT: return _module.op(hdl::Op::Kind::LtU, {b, a}); break;
        case llvm::CmpInst::ICMP_UGE: return _module.op(hdl::Op::Kind::LeU, {b, a}); break;
        case llvm::CmpInst::ICMP_ULT: return _module.op(hdl::Op::Kind::LtU, {a, b}); break;
        case llvm::CmpInst::ICMP_ULE: return _module.op(hdl::Op::Kind::LeU, {a, b}); break;
        case llvm::CmpInst::ICMP_SGT: return _module.op(hdl::Op::Kind::LtS, {b, a}); break;
        case llvm::CmpInst::ICMP_SGE: return _module.op(hdl::Op::Kind::LeS, {b, a}); break;
        case llvm::CmpInst::ICMP_SLT: return _module.op(hdl::Op::Kind::LtS, {a, b}); break;
        case llvm::CmpInst::ICMP_SLE: return _module.op(hdl::Op::Kind::LeS, {a, b}); break;
        default:
          throw_error(Error, "Predicate " << llvm::CmpInst::getPredicateName(predicate).str() << " is not implemented");
      }
    }
    
    void trace_cmp(llvm::CmpInst* cmp) {
      StackFrame& frame = _stack.back();
      Value a = frame[cmp->getOperand(0)];
      Value b = frame[cmp->getOperand(1)];
      hdl::Value* result = trace_cmp(cmp->getPredicate(), a.primitive(), b.primitive());
      frame.set(cmp, Value(result));
    }
    
    hdl::Value* slice(hdl::Value* value, size_t offset, size_t width) {
      return _module.op(hdl::Op::Kind::Slice, {
        value,
        _module.constant(hdl::BitString::from_uint(offset)),
        _module.constant(hdl::BitString::from_uint(width))
      });
    }
    
    hdl::Value* mul(hdl::Value* a, hdl::Value* b) {
      if (a->width != b->width) {
        throw_error(Error, "Width mismatch for mul");
      }
      return slice(_module.op(hdl::Op::Kind::Mul, {a, b}), 0, a->width);
    }
    
    hdl::Value* zext(hdl::Value* value, size_t to) {
      if (to < value->width) {
        throw_error(Error, "Unable to zero extend value of width " << value->width << " to width " << to);
      }
      
      size_t delta = to - value->width;
      return _module.op(hdl::Op::Kind::Concat, {
        _module.constant(hdl::BitString(delta)),
        value
      });
    }
    
    hdl::Value* resize_u(hdl::Value* value, size_t to) {
      if (to == value->width) {
        return value;
      } else if (to > value->width) {
        return zext(value, to);
      } else {
        return slice(value, 0, to);
      }
    }
    
    void trace_cast(llvm::CastInst* cast) {
      StackFrame& frame = _stack.back();
      Value value = frame[cast->getOperand(0)];
      size_t dest_width = cast->getDestTy()->getPrimitiveSizeInBits();
      size_t src_width = cast->getSrcTy()->getPrimitiveSizeInBits();
      
      if (llvm_match(ZExtInst, z_ext, cast)) {
        frame.set(cast, Value(zext(value.primitive(), dest_width)));
      } else if (llvm_match(SExtInst, s_ext, cast)) {
        size_t delta = dest_width - src_width;
        frame.set(cast, Value(_module.op(hdl::Op::Kind::Concat, {
          _module.op(hdl::Op::Kind::Select, {
            slice(value.primitive(), src_width - 1, 1),
            _module.constant(~hdl::BitString(delta)),
            _module.constant(hdl::BitString(delta))
          }),
          value.primitive()
        })));
      } else if (llvm_match(TruncInst, trunc, cast)) {
        frame.set(cast, Value(slice(value.primitive(), 0, dest_width)));
      } else if (cast->isNoopCast(cast->getModule()->getDataLayout())) {
        frame.set(cast, value);
      } else {
        throw_error(Error, "Cast instruction " << cast->getOpcodeName() << " is not implemented");
      }
    }
    
    void trace_intrinsic(llvm::IntrinsicInst* intrinsic) {
      StackFrame& frame = _stack.back();
      
      if (llvm_match(LifetimeIntrinsic, lifetime, intrinsic)) {
        // Ignore
      } else if (llvm_match(MinMaxIntrinsic, min_max, intrinsic)) {
        hdl::Value* lhs = frame[min_max->getLHS()].primitive();
        hdl::Value* rhs = frame[min_max->getRHS()].primitive();
        hdl::Value* cond = trace_cmp(min_max->getPredicate(), lhs, rhs);
        frame.set(intrinsic, _module.op(hdl::Op::Kind::Select, {
          cond, lhs, rhs
        }));
      } else if (llvm_match(MemCpyInst, memcpy, intrinsic)) {
        hdl::Constant* length_constant = dynamic_cast<hdl::Constant*>(frame[memcpy->getLength()].primitive());
        if (!length_constant) {
          throw_error(Error, "");
        }
        size_t length = length_constant->value.as_uint64();
        hdl::Value* source = frame[memcpy->getSource()].primitive();
        hdl::Value* dest = frame[memcpy->getDest()].primitive();
        for (size_t offset = 0; offset < length; offset++) {
          hdl::Value* offset_value = _module.constant(hdl::BitString::from_uint(offset));
          offset_value = resize_u(offset_value, source->width);
          _memory.store(
            _module.op(hdl::Op::Kind::Add, {dest, offset_value}),
            _memory.load(_module.op(hdl::Op::Kind::Add, {source, offset_value}), &_exceptions),
            &_exceptions
          );
        }
      } else if (llvm_match(MemSetInst, memset, intrinsic)) {
        hdl::Constant* length_constant = dynamic_cast<hdl::Constant*>(frame[memset->getLength()].primitive());
        if (!length_constant) {
          throw_error(Error, "");
        }
        size_t length = length_constant->value.as_uint64();
        hdl::Value* value = frame[memset->getValue()].primitive();
        hdl::Value* dest = frame[memset->getDest()].primitive();
        if (value->width != 8) {
          throw_error(Error, "");
        }
        for (size_t offset = 0; offset < length; offset++) {
          hdl::Value* offset_value = _module.constant(hdl::BitString::from_uint(offset));
          offset_value = resize_u(offset_value, dest->width);
          _memory.store(_module.op(hdl::Op::Kind::Add, {dest, offset_value}), value, &_exceptions);
        }
      } else if (intrinsic->getIntrinsicID() == llvm::Intrinsic::fshl) {
        hdl::Value* a = frame[intrinsic->getArgOperand(0)].primitive();
        hdl::Value* b = frame[intrinsic->getArgOperand(1)].primitive();
        hdl::Value* c = frame[intrinsic->getArgOperand(2)].primitive();
        
        frame.set(intrinsic, slice(_module.op(hdl::Op::Kind::Shl, { 
          _module.op(hdl::Op::Kind::Concat, {a, b}),
          c
        }), b->width, a->width));
      } else {
        throw_error(Error, "Intrinsic " << intrinsic->getCalledFunction()->getName().str() << " is not implemented");
      }
    }
    
    enum class StopReason {
      ToplevelReturn, Branch, Join
    };
    
    StopReason trace_until_branch() {
      while (true) {
        llvm::Instruction* inst = current_inst();
        if (_stack.back().is_join(inst->getParent())) {
          return StopReason::Join;
        }
        
        #ifdef PATHBEAVER_DEBUG
        inst->print(llvm::outs());
        llvm::outs() << '\n';
        #endif
        
        _exceptions.set_current_source(inst);
        
        if (llvm_match(ReturnInst, ret, inst)) {
          StackFrame& callee_frame = _stack.back();
          for (hdl::Unknown* base_address : callee_frame.allocations) {
            _memory.dealloc(base_address);
          }
          
          if (_stack.size() == 1) {
            StackFrame frame(_module, _globals);
            frame.pc = nullptr;
            if (ret->getReturnValue() != nullptr) {
              frame.set(nullptr, callee_frame[ret->getReturnValue()]);
            }
            _stack.pop_back();
            _stack.push_back(frame);
            return StopReason::ToplevelReturn;
          }
          StackFrame& caller_frame = _stack[_stack.size() - 2];
          if (ret->getReturnValue() != nullptr) {
            caller_frame.set(caller_frame.pc, callee_frame[ret->getReturnValue()]);
          }
          caller_frame.next();
          _stack.pop_back();
        } else if (llvm_match(BranchInst, branch, inst)) {
          if (branch->isConditional()) {
            return StopReason::Branch;
          }
          enter(branch->getSuccessor(0), branch->getParent());
        } else if (llvm_match(CallInst, call_inst, inst)) {
          StackFrame& frame = _stack.back();
          if (llvm_match(IntrinsicInst, intrinsic, inst)) {
            trace_intrinsic(intrinsic);
            frame.next();
          } else {
            llvm::Function* callee = call_inst->getCalledFunction();
            if (callee == nullptr) {
              hdl::Value* callee_value = frame[call_inst->getCalledOperand()].primitive();
              hdl::Unknown* unknown = dynamic_cast<hdl::Unknown*>(callee_value);
              if (unknown == nullptr) {
                throw_error(Error, "");
              }
              callee = _globals.function(unknown);
            }
            std::vector<Value> args;
            args.reserve(call_inst->arg_size());
            for (llvm::Value* arg : call_inst->args()) {
              args.push_back(frame[arg]);
            }
            call(callee, args);
          }
        } else if (llvm_match(SelectInst, select, inst)) {
          StackFrame& frame = _stack.back();
          Value cond = frame[select->getCondition()];
          Value a = frame[select->getTrueValue()];
          Value b = frame[select->getFalseValue()];
          frame.set(inst, _module.op(hdl::Op::Kind::Select, {
            cond.primitive(), a.primitive(), b.primitive()
          }));
          frame.next();
        } else if (llvm_match(GetElementPtrInst, gep, inst)) {
          StackFrame& frame = _stack.back();
          hdl::Value* pointer = frame[gep->getPointerOperand()].primitive();
          
          const llvm::DataLayout& data_layout = gep->getModule()->getDataLayout();
          size_t pointer_width = data_layout.getPointerSizeInBits();
          
          llvm::MapVector<llvm::Value*, llvm::APInt> variable_offsets;
          llvm::APInt constant_offset = llvm::APInt().zext(pointer_width);
          bool success = gep->collectOffset(data_layout, pointer_width, variable_offsets, constant_offset);
          if (!success) {
            throw_error(Error, "Not supported");
          }
          
          pointer = _module.op(hdl::Op::Kind::Add, {
            pointer,
            _module.constant(ap_int_to_bit_string(constant_offset))
          });
          
          for (const auto& [value, factor] : variable_offsets) {
            pointer = _module.op(hdl::Op::Kind::Add, {
              pointer,
              mul(
                _module.constant(ap_int_to_bit_string(factor)),
                frame[value].primitive()
              )
            });
          }
          
          frame.set(inst, pointer);
          frame.next();
        } else if (llvm_match(AllocaInst, alloca, inst)) {
          StackFrame& frame = _stack.back();
          hdl::Value* array_size = frame[alloca->getArraySize()].primitive();
          
          const llvm::DataLayout& data_layout = alloca->getModule()->getDataLayout();
          size_t pointer_width = data_layout.getPointerSizeInBits();
          size_t alloc_size = data_layout.getTypeAllocSize(alloca->getAllocatedType());
          
          hdl::Value* size = mul(
            resize_u(_module.constant(hdl::BitString::from_uint(alloc_size)), pointer_width),
            resize_u(array_size, pointer_width)
          );
          hdl::Unknown* base_address = _memory.alloc(size);
          
          frame.set(alloca, base_address);
          frame.allocations.push_back(base_address);
          _stack.back().next();
        } else if (llvm_match(StoreInst, store, inst)) {
          StackFrame& frame = _stack.back();
          Value value = frame[store->getValueOperand()];
          hdl::Value* pointer = frame[store->getPointerOperand()].primitive();
          
          const llvm::DataLayout& data_layout = store->getModule()->getDataLayout();
          std::map<size_t, hdl::Value*> layout = value.to_bytes(store->getValueOperand()->getType(), data_layout, _module);
          for (const auto& [offset, byte] : layout) {
            hdl::Value* offset_value = _module.constant(hdl::BitString::from_uint(offset));
            hdl::Value* address = _module.op(hdl::Op::Kind::Add, {
              pointer,
              resize_u(offset_value, pointer->width)
            });
            _memory.store(address, byte, &_exceptions);
          }
          _stack.back().next();
        } else if (llvm_match(LoadInst, load, inst)) {
          StackFrame& frame = _stack.back();
          hdl::Value* pointer = frame[load->getPointerOperand()].primitive();
          
          const llvm::DataLayout& data_layout = load->getModule()->getDataLayout();
          llvm::Type* type = load->getType();
          size_t size = data_layout.getTypeStoreSize(type);
          std::vector<hdl::Value*> bytes;
          bytes.reserve(size);
          for (size_t offset = 0; offset < size; offset++) {
            hdl::Value* offset_value = _module.constant(hdl::BitString::from_uint(offset));
            hdl::Value* address = _module.op(hdl::Op::Kind::Add, {
              pointer,
              resize_u(offset_value, pointer->width)
            });
            bytes.push_back(_memory.load(address, &_exceptions));
          }
          
          frame.set(load, Value::from_bytes(type, data_layout, bytes, _module));
          _stack.back().next();
        } else if (llvm_match(BinaryOperator, binop, inst)) {
          trace_binop(binop);
          _stack.back().next();
        } else if (llvm_match(CmpInst, cmp, inst)) {
          trace_cmp(cmp);
          _stack.back().next();
        } else if (llvm_match(CastInst, cast, inst)) {
          trace_cast(cast);
          _stack.back().next();
        } else {
          throw_error(Error, "Instruction " << inst->getOpcodeName() << " is not supported.");
        }
      }
    }
    
    std::vector<Trace> split_at_branch() {
      std::vector<Trace> traces;
      StackFrame& frame = _stack.back();
      llvm::Instruction* inst = frame.pc;
      
      if (llvm_match(BranchInst, branch, inst)) {
        Trace then_trace = *this;
        if (then_trace._requirements.require(frame[branch->getCondition()].primitive())) {
          then_trace.enter(branch->getSuccessor(0), branch->getParent());
          traces.push_back(then_trace);
        }
        
        Trace else_trace = *this;
        if (else_trace._requirements.require_not(frame[branch->getCondition()].primitive())) {
          else_trace.enter(branch->getSuccessor(1), branch->getParent());
          traces.push_back(else_trace);
        }
      } else {
        throw_error(Error, "Instruction " << inst->getOpcodeName() << " is not a supported branch instruction.");
      }
      
      return traces;
    }
    
    static llvm::BasicBlock* find_join_block(const std::vector<Trace>& traces) {
      if (traces.size() == 0) {
        return nullptr;
      }
      
      llvm::Function* function = traces[0].current_inst()->getParent()->getParent();
      llvm::PostDominatorTree postdom(*function);
      
      llvm::BasicBlock* join = traces[0].current_inst()->getParent();
      for (size_t it = 1; it < traces.size(); it++) {
        llvm::BasicBlock* block = traces[it].current_inst()->getParent();
        join = postdom.findNearestCommonDominator(join, block);
      }
      
      return join;
    }
    
    std::vector<Trace> trace() {
      std::vector<Trace> traces;
      
      std::deque<Trace> open;
      open.push_back(*this);
      while (!open.empty()) {
        Trace trace = open.front();
        open.pop_front();
        
        StopReason reason = trace.trace_until_branch();
        if (reason == StopReason::Branch) {
          std::vector<Trace> options = trace.split_at_branch();
          for (const Trace& option : options) {
            open.push_back(option);
          }
        } else {
          traces.push_back(trace);
        }
      }
      
      return traces;
    }
    
    Trace trace_recursive() {
      #ifdef PATHBEAVER_DEBUG
      std::cout << "Trace" << std::endl;
      #endif
      
      Trace trace = *this;
      StopReason reason = trace.trace_until_branch();
      while (reason == StopReason::Branch) {
        std::vector<Trace> options = trace.split_at_branch();
        llvm::BasicBlock* join = find_join_block(options);
        
        #ifdef PATHBEAVER_DEBUG
        llvm::outs() << "Branch. Rejoin at: ";
        join->printAsOperand(llvm::outs());
        llvm::outs() << '\n';
        #endif
        
        std::vector<Trace> joined;
        for (Trace& option : options) {
          if (join != nullptr) {
            option._stack.back().joins.push_back(join);
          }
          Trace done = option.trace_recursive();
          if (join != nullptr) {
            if (done._stack.back().joins.back() != join) {
              throw_error(Error, "");
            }
            done._stack.back().joins.pop_back();
          }
          joined.push_back(done);
        }
        
        #ifdef PATHBEAVER_DEBUG
        std::cout << "Rejoined" << std::endl;
        #endif
        
        std::optional<Trace> merged = Trace::merge(joined);
        move_into(trace, std::move(merged.value()));
        reason = trace.trace_until_branch();
      }
      
      return trace;
    }
    
    bool merge_inplace(const Trace& other) {
      if (_stack.size() != other._stack.size()) {
        return false;
      }
      
      hdl::Value* cond = _requirements.difference(other._requirements).build();
      
      for (size_t it = 0; it < _stack.size(); it++) {
        StackFrame& frame = _stack[it];
        const StackFrame& other_frame = other._stack[it];
        
        if (frame.pc != other_frame.pc) {
          return false;
        }
        
        if (frame.joins.size() != other_frame.joins.size()) {
          return false;
        }
        
        for (size_t it = 0; it < frame.joins.size(); it++) {
          if (frame.joins[it] != other_frame.joins[it]) {
            return false;
          }
        }
        
        for (auto iter = frame.values.begin(); iter != frame.values.end(); ) {
          auto& [llvm_value, value] = *iter;
          if (other_frame.values.find(llvm_value) == other_frame.values.end()) {
            iter = frame.values.erase(iter);
          } else {
            const Value& other_value = other_frame.values.at(llvm_value);
            if (value.kind() != other_value.kind()) {
              return false;
            }
            value = _module.op(hdl::Op::Kind::Select, {
              cond, value.primitive(), other_value.primitive()
            });
            iter++;
          }
        }
      }
      
      if (!_memory.merge_inplace(other._memory, cond)) {
        return false;
      }
      
      _exceptions.merge_inplace(other._exceptions, cond);
      _requirements = _requirements.merge(other._requirements);
      
      return true;
    }
  };
}

#undef llvm_match
#undef throw_error

#endif
