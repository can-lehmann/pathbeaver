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
#include <llvm/IR/Constants.h>

#include <llvm/Analysis/PostDominators.h>

#include "../modules/hdl.cpp/hdl.hpp"

#define throw_error(Error, msg) {\
  std::ostringstream message_stream; \
  message_stream << msg; \
  throw Error(message_stream.str()); \
}

#define llvm_match(Type, into, value) llvm::Type* into = llvm::dyn_cast<llvm::Type>(value)

namespace pathbeaver {
  template <class T>
  void move_into(T& into, T&& value) {
    into.~T();
    new(&into) T(std::move(value));
  }

  class Error: public std::runtime_error {
    using std::runtime_error::runtime_error;
  };
  
  using Id = uint64_t;
  
  class Value {
  public:
    enum class Kind {
      Primitive, Pointer, Unknown, Select
    };
    
    struct Unknown {
      size_t size = 0;
      Unknown(size_t _size): size(_size) {}
    };
    
    struct Pointer {
      Id id = 0;
      hdl::Value* offset = nullptr;
      
      Pointer(Id _id, hdl::Value* _offset): id(_id), offset(_offset) {}
    };
    
    struct Select {
      hdl::Value* cond = nullptr;
      std::shared_ptr<Value> a;
      std::shared_ptr<Value> b;
      
      Select(hdl::Value* _cond,
             const std::shared_ptr<Value>& _a,
             const std::shared_ptr<Value>& _b):
        cond(_cond), a(_a), b(_b) {}
    };
  private:
    std::variant<hdl::Value*, Pointer, Unknown, Select> _value;
  public:
    Value(hdl::Value* value): _value(value) {}
    Value(const Pointer& value): _value(value) {}
    Value(const Unknown& value): _value(value) {}
    Value(const Select& value): _value(value) {}
    
    static Value select(hdl::Value* cond, const Value& a, const Value& b, hdl::Module& module) {
      if (hdl::Constant* constant = dynamic_cast<hdl::Constant*>(cond)) {
        if (constant->value.is_zero()) {
          return b;
        } else {
          return a;
        }
      } else if (a.kind() == Kind::Primitive && b.kind() == Kind::Primitive) {
        return module.op(hdl::Op::Kind::Select, {
          cond,
          a.primitive(),
          b.primitive()
        });
      } else {
        return Value(Select(cond, std::make_shared<Value>(a), std::make_shared<Value>(b)));
      }
    }
    
    static Value from_bytes(llvm::Type* type,
                            const llvm::DataLayout& data_layout,
                            const std::vector<Value>& bytes,
                            hdl::Module& module) {
      size_t size = data_layout.getTypeStoreSize(type);
      switch (bytes[0].kind()) {
        case Kind::Primitive: {
          hdl::Value* value = nullptr;
          for (size_t offset = 0; offset < size; offset++) {
            hdl::Value* byte = bytes[offset].primitive();
            
            if (value == nullptr) {
              value = byte;
            } else {
              if (data_layout.isLittleEndian()) {
                value = module.op(hdl::Op::Kind::Concat, {byte, value});
              } else {
                value = module.op(hdl::Op::Kind::Concat, {value, byte});
              }
            }
          }
          return Value(value);
        }
        break;
        case Kind::Pointer: return bytes[0]; break;
        case Kind::Unknown: return Value(Unknown(size)); break;
        case Kind::Select: throw_error(Error, ""); break;
      }
    }
    
    Kind kind() const { return Kind(_value.index()); }
    hdl::Value* primitive() const { return std::get<hdl::Value*>(_value); }
    Pointer pointer() const { return std::get<Pointer>(_value); }
    Select select() const { return std::get<Select>(_value); }
    
    std::map<size_t, Value> to_bytes(llvm::Type* type,
                                     const llvm::DataLayout& data_layout,
                                     hdl::Module& module) {
      std::map<size_t, Value> layout;
      size_t size = data_layout.getTypeStoreSize(type);
      switch (kind()) {
        case Kind::Primitive:
          for (size_t offset = 0; offset < size; offset++) {
            hdl::Value* byte = module.op(hdl::Op::Kind::Slice, {
              primitive(),
              module.constant(hdl::BitString::from_uint(offset * 8)),
              module.constant(hdl::BitString::from_uint(8))
            });
            if (data_layout.isLittleEndian()) {
              layout.insert({offset, Value(byte)});
            } else {
              layout.insert({size - offset - 1, Value(byte)});
            }
          }
        break;
        case Kind::Pointer:
          for (size_t offset = 0; offset < size; offset++) {
            layout.insert({offset, *this});
          }
        break;
        case Kind::Unknown:
          for (size_t offset = 0; offset < size; offset++) {
            layout.insert({offset, Value(Unknown(1))});
          }
        break;
        case Kind::Select:
          throw_error(Error, "");
        break;
      }
      return layout;
    }
  };
  
  class Memory {
  public:
    struct Write {
      hdl::Value* enable = nullptr;
      hdl::Value* address = nullptr;
      Value value;
      
      Write(hdl::Value* _enable, hdl::Value* _address, const Value& _value):
        enable(_enable), address(_address), value(_value) {}
    };
    
    struct Chunk {
      hdl::Module* module = nullptr;
      hdl::Value* size = nullptr;
      std::vector<Write> writes;
      
      Chunk(hdl::Module* _module, hdl::Value* _size): module(_module), size(_size) {}
      
      void store(hdl::Value* address, Value value) {
        writes.emplace_back(
          module->constant(hdl::BitString::from_bool(true)),
          address,
          value
        );
      }
      
      Value load(hdl::Value* address) {
        Value result(Value::Unknown(1));
        for (const Write& write : writes) {
          result = Value::select(
            module->op(hdl::Op::Kind::And, {
              write.enable,
              module->op(hdl::Op::Kind::Eq, {
                address,
                write.address
              })
            }),
            write.value,
            result,
            *module
          );
        }
        return result;
      }
    };
  private:
    hdl::Module* _module = nullptr;
    Id _max_id = 0;
    std::map<Id, Chunk> _chunks;
  public:
    Memory(hdl::Module* module): _module(module) {}
    
    Id alloc(hdl::Value* size) {
      Id id = ++_max_id;
      _chunks.insert({id, Chunk(_module, size)});
      return id;
    }
    
    void dealloc(Id id) {
      _chunks.erase(id);
    }
    
    Chunk& operator[](Id id) { return _chunks.at(id); }
    const Chunk& operator[](Id id) const { return _chunks.at(id); }
  };
  
  class Trace {
  public:
    struct StackFrame {
      hdl::Module& module;
      llvm::Instruction* pc = nullptr;
      std::vector<llvm::BasicBlock*> joins;
      std::unordered_map<llvm::Value*, Value> values;
      std::vector<Id> allocations;
      
      StackFrame(hdl::Module& _module): module(_module) {}
      
      Value operator[](llvm::Value* value) const {
        if (llvm_match(Constant, constant, value)) {
          if (llvm_match(ConstantInt, constant_int, value)) {
            hdl::BitString bit_string(constant_int->getBitWidth());
            for (size_t it = 0; it < bit_string.width(); it++) {
              bit_string.set(it, constant_int->getValue()[it]);
            }
            return module.constant(bit_string);
          } else {
            throw_error(Error, "Unknown constant");
          }
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
    Requirements _requirements;
    std::vector<StackFrame> _stack;
    Memory _memory;
  public:
    Trace(hdl::Module& module): _module(module), _requirements(&module), _memory(&module) {}
    
    static Trace call(hdl::Module& module,
                      llvm::Function* function,
                      const std::vector<Value>& args) {
      Trace trace(module);
      trace.call(function, args);
      return trace;
    }
    
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
    const std::vector<StackFrame>& stack() const { return _stack; }
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
      
      StackFrame frame(_module);
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
      } else {
        throw_error(Error, "Cast instruction " << cast->getOpcodeName() << " is not implemented");
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
        inst->print(llvm::outs());
        llvm::outs() << '\n';
        
        if (llvm_match(ReturnInst, ret, inst)) {
          StackFrame& callee_frame = _stack.back();
          for (Id id : callee_frame.allocations) {
            _memory.dealloc(id);
          }
          
          if (_stack.size() == 1) {
            StackFrame frame(_module);
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
        } else if (llvm_match(SelectInst, select, inst)) {
          StackFrame& frame = _stack.back();
          Value cond = frame[select->getCondition()];
          Value a = frame[select->getTrueValue()];
          Value b = frame[select->getFalseValue()];
          frame.set(inst, Value::select(cond.primitive(), a, b, _module));
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
          Id id = _memory.alloc(size);
          
          hdl::Value* offset = _module.constant(hdl::BitString(pointer_width));
          frame.set(alloca, Value(Value::Pointer(id, offset)));
          frame.allocations.push_back(id);
          _stack.back().next();
        } else if (llvm_match(StoreInst, store, inst)) {
          StackFrame& frame = _stack.back();
          Value value = frame[store->getValueOperand()];
          Value::Pointer pointer = frame[store->getPointerOperand()].pointer();
          
          const llvm::DataLayout& data_layout = store->getModule()->getDataLayout();
          std::map<size_t, Value> layout = value.to_bytes(store->getValueOperand()->getType(), data_layout, _module);
          for (const auto& [offset, byte] : layout) {
            hdl::Value* offset_value = _module.constant(hdl::BitString::from_uint(offset));
            hdl::Value* address = _module.op(hdl::Op::Kind::Add, {
              pointer.offset,
              resize_u(offset_value, pointer.offset->width)
            });
            _memory[pointer.id].store(address, byte);
          }
          _stack.back().next();
        } else if (llvm_match(LoadInst, load, inst)) {
          StackFrame& frame = _stack.back();
          Value::Pointer pointer = frame[load->getPointerOperand()].pointer();
          
          const llvm::DataLayout& data_layout = load->getModule()->getDataLayout();
          llvm::Type* type = load->getType();
          size_t size = data_layout.getTypeStoreSize(type);
          std::vector<Value> bytes;
          bytes.reserve(size);
          for (size_t offset = 0; offset < size; offset++) {
            hdl::Value* offset_value = _module.constant(hdl::BitString::from_uint(offset));
            hdl::Value* address = _module.op(hdl::Op::Kind::Add, {
              pointer.offset,
              resize_u(offset_value, pointer.offset->width)
            });
            bytes.push_back(_memory[pointer.id].load(address));
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
      join->printAsOperand(llvm::outs());
      llvm::outs() << '\n';
      for (size_t it = 1; it < traces.size(); it++) {
        llvm::BasicBlock* block = traces[it].current_inst()->getParent();
        block->printAsOperand(llvm::outs());
        llvm::outs() << '\n';
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
      std::cout << "Trace" << std::endl;
      Trace trace = *this;
      StopReason reason = trace.trace_until_branch();
      while (reason == StopReason::Branch) {
        std::vector<Trace> options = trace.split_at_branch();
        llvm::BasicBlock* join = find_join_block(options);
        
        llvm::outs() << "Branch. Rejoin at: ";
        join->printAsOperand(llvm::outs());
        llvm::outs() << '\n';
        
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
        
        std::cout << "Rejoined" << std::endl;
        
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
            value = Value::select(cond, value, other_value, _module);
            iter++;
          }
        }
      }
      
      _requirements = _requirements.merge(other._requirements);
      
      return true;
    }
    
    
  };
}

#undef llvm_match
#undef throw_error

#endif
