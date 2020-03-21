#pragma once

#include "register.hpp"


#include <vector>
#include <string>
#include <iostream>
#include <bitset>

class Instruction {
	public:
		template<typename T, typename...ARGS>
		Instruction(int64_t * imm, T const & arg0, ARGS const & ...args) {
			this->imm = imm;
			this->regs = std::vector<Register *>({arg0, args...});
		}
		template<typename T, typename...ARGS>
		Instruction(T const & arg0, ARGS const & ...args) {
			this->imm = NULL;
			this->regs = std::vector<Register *>({arg0, args...});
		}
		Instruction(void);
		virtual ~Instruction();
		std::vector<Register* > regs;
		int64_t * imm;
};

class MPCInstruction : public Instruction {
	public:
		template<typename T, typename...ARGS>
		MPCInstruction(int64_t * imm, T const & arg0, ARGS const & ...args) {
			this->imm = imm;
			this->regs = std::vector<T>({arg0, args...});
		}
		MPCInstruction(void);
		~MPCInstruction();
};

class HCFInstruction : public Instruction {
	public:
		template<typename T, typename...ARGS>
		HCFInstruction(T const & arg0, ARGS const & ...args) {
			this->regs = std::vector<T>({arg0, args...});
		}
		HCFInstruction(void);
		~HCFInstruction();
};

class ENQInstruction : public Instruction {
	public:
		template<typename T, typename...ARGS>
		ENQInstruction(T const & arg0, ARGS const & ...args) {
			this->imm = NULL;
			this->regs = std::vector<T>({arg0, args...});
		}
		template<typename T, typename...ARGS>
		ENQInstruction(int64_t * imm, T const & arg0, ARGS const & ...args) {
			this->imm = imm;
			this->regs = std::vector<T>({arg0, args...});
		}
		ENQInstruction(void);
		~ENQInstruction();
};

class DEQInstruction : public Instruction {
	public:
		template<typename T, typename...ARGS>
		DEQInstruction(T const & arg0, ARGS const & ...args) {
			this->imm = NULL;
			this->regs = std::vector<T>({arg0, args...});
		}
		template<typename T, typename...ARGS>
		DEQInstruction(int64_t * imm, T const & arg0, ARGS const & ...args) {
			this->imm = imm;
			this->regs = std::vector<T>({arg0, args...});
		}
		DEQInstruction(void);
		~DEQInstruction(void);
};

class JSZInstruction : public Instruction {
	public:
		template<typename T, typename...ARGS>
		JSZInstruction(T const & arg0, ARGS const & ...args) {
			this->regs = std::vector<T>({arg0, args...});
		}
		JSZInstruction(void);
		~JSZInstruction();
};

class ALLRMRPCIVRIInstruction : public Instruction {
	public:
		template<typename T, typename...ARGS>
		ALLRMRPCIVRIInstruction(int64_t * imm, int64_t * imm1, T const & arg0, ARGS const & ...args) {
			this->imm = imm;
			this->imm1 = imm1;
			this->regs = std::vector<T>({arg0, args...});
		}
		template<typename T, typename...ARGS>
		ALLRMRPCIVRIInstruction(T const & arg0, ARGS const & ...args) {
			this->imm = NULL;
			this->imm1 = NULL;
			this->regs = std::vector<T>({arg0, args...});
		}
		ALLRMRPCIVRIInstruction(void);
		~ALLRMRPCIVRIInstruction();
		void invert(void);
		int64_t * imm1;
};

class MOOQInstruction : public Instruction {
	public:
		MOOQInstruction(void);
		~MOOQInstruction();
	private:
};

class RVInstruction : public Instruction {
	public:
		template<typename T, typename...ARGS>
		RVInstruction(T const & arg0, ARGS const & ...args) {
			this->imm = NULL;
			this->regs = std::vector<T>({arg0, args...});
		}
		template<typename T, typename...ARGS>
		RVInstruction(int64_t * imm, T const & arg0, ARGS const & ...args) {
			this->imm = imm;
			this->regs = std::vector<T>({arg0, args...});
		}
		RVInstruction(void);
		~RVInstruction();
};

class LARInstruction : public Instruction {
	public:
		template<typename T, typename...ARGS>
		LARInstruction(int64_t * imm, T const & arg0, ARGS const & ...args) {
			this->imm = imm;
			this->regs = std::vector<T>({arg0, args...});
		}
		LARInstruction(void);
		~LARInstruction();
	private:
};
		
class AMLInstruction: public Instruction {
	public:
		template<typename T, typename...ARGS>
		AMLInstruction(T const & arg0, ARGS const & ...args) {
			this->imm = NULL;
			this->regs = std::vector<T>({arg0, args...});
		}
		AMLInstruction(int64_t * imm) {
			this->imm = imm;
			this->regs = std::vector<Register *>();
		}
		AMLInstruction(void);
		~AMLInstruction();
};

class GMLInstruction: public Instruction {
	public:
		template<typename T, typename...ARGS>
		GMLInstruction(T const & arg0, ARGS const & ...args) {
			this->imm = NULL;
			this->regs = std::vector<T>({arg0, args...});
		}
		GMLInstruction(int64_t * imm);
		GMLInstruction(void);
		~GMLInstruction();
};

class SQInstruction: public Instruction {
	public:
		template<typename T, typename...ARGS>
		SQInstruction(T const & arg0, ARGS const & ...args) {
			this->imm = NULL;
			this->regs = std::vector<T>({arg0, args...});
		}
		SQInstruction(int64_t * imm);
		SQInstruction(void);
		~SQInstruction();
};

class EMPInstruction: public Instruction {
	public:
		template<typename T, typename...ARGS>
		EMPInstruction(int64_t * imm, T const & arg0, ARGS const & ...args) {
			this->imm = imm;
			this->regs = std::vector<T>({arg0, args...});
		}
		EMPInstruction(void);
		~EMPInstruction();
};
