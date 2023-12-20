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
#include <stdexcept>
#include <sstream>
#include <variant>
#include <deque>
#include <optional>

#include <llvm/IR/Module.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>

#include "../modules/hdl.cpp/hdl.hpp"

#define throw_error(Error, msg) {\
  std::ostringstream message_stream; \
  message_stream << msg; \
  throw Error(message_stream.str()); \
}

#define llvm_match(Type, into, value) llvm::Type* into = llvm::dyn_cast<llvm::Type>(value)

namespace pathbeaver {
  class Error: public std::runtime_error {
    using std::runtime_error::runtime_error;
  };
  
  class Value {
  public:
    enum class Kind {
      Primitive
    };
  private:
    std::variant<hdl::Value*> _value;
  public:
    Value(hdl::Value* value): _value(value) {}
    
    Kind kind() const { return Kind(_value.index()); }
    hdl::Value* primitive() const { return std::get<hdl::Value*>(_value); }
    
  };
  
  
  class Trace {
  public:
    struct StackFrame {
      hdl::Module& module;
      llvm::Instruction* pc = nullptr;
      std::unordered_map<llvm::Value*, Value> values;
      
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
  public:
    Trace(hdl::Module& module): _module(module), _requirements(&module) {}
    
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
          if (trace.merge_inplace(traces[it])) {
            return {};
          }
        }
      }
      return trace;
    }
    
    hdl::Module& module() const { return _module; }
    const Requirements& requirements() const { return _requirements; }
    const std::vector<StackFrame>& stack() const { return _stack; }
    
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
    
    enum class StopReason {
      ToplevelReturn, Branch
    };
    
    StopReason trace_until_branch() {
      while (true) {
        llvm::Instruction* inst = _stack.back().pc;
        inst->print(llvm::outs());
        llvm::outs() << '\n';
        
        if (llvm_match(ReturnInst, ret, inst)) {
          StackFrame& callee_frame = _stack.back();
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
          if (cond.kind() != Value::Kind::Primitive ||
              a.kind() != Value::Kind::Primitive ||
              b.kind() != Value::Kind::Primitive) {
            throw_error(Error, "");
          }
          frame.set(inst, _module.op(hdl::Op::Kind::Select, {
            cond.primitive(),
            a.primitive(),
            b.primitive()
          }));
          frame.next();
        } else if (llvm_match(BinaryOperator, binop, inst)) {
          trace_binop(binop);
          _stack.back().next();
        } else if (llvm_match(CmpInst, cmp, inst)) {
          trace_cmp(cmp);
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
    
    std::vector<Trace> trace() {
      std::vector<Trace> traces;
      
      std::deque<Trace> open;
      open.push_back(*this);
      while (!open.empty()) {
        Trace trace = open.front();
        open.pop_front();
        
        StopReason reason = trace.trace_until_branch();
        if (reason == StopReason::Branch) {
          for (const Trace& option : trace.split_at_branch()) {
            open.push_back(option);
          }
        } else {
          traces.push_back(trace);
        }
      }
      
      return traces;
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
        
        for (auto iter = frame.values.begin(); iter != frame.values.end(); ) {
          auto& [llvm_value, value] = *iter;
          if (other_frame.values.find(llvm_value) == other_frame.values.end()) {
            iter = frame.values.erase(iter);
          } else {
            const Value& other_value = other_frame.values.at(llvm_value);
            if (value.kind() != other_value.kind()) {
              return false;
            }
            switch (value.kind()) {
              case Value::Kind::Primitive:
                value = Value(_module.op(hdl::Op::Kind::Select, {
                  cond,
                  value.primitive(),
                  other_value.primitive()
                }));
              break;
            }
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
