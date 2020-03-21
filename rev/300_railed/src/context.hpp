#pragma once

#include "register.hpp"
#include "instruction.hpp"

#include <queue>
#include <vector>
#include <bit>
#include <bitset>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iomanip>
#include <utility>

class Context {
	public:
		Context(std::vector<Instruction *> * code);
		Context();
		void add_instruction(Instruction * ins);
		Register * get_reg(std::string regname);
		void printstate(void);
		void update_reg(Register * r, int64_t value);
		void enqueue(Register * r);
		void enqueue(int64_t value);
		void dequeue(void);
		void dequeue(Register * r);
		int64_t queue_front(void);
		size_t queue_size(void);
		void halt(void);
		~Context();

		/* Instruction Entrypoint */
		void run(void);
		void execute(Instruction * i);
		

		/* Instructions */
		void mpc(MPCInstruction * ins);
		void hcf(HCFInstruction * ins);
		void deq(DEQInstruction * ins);
		void enq(ENQInstruction * ins);
		void jsz(JSZInstruction * ins);
		void allrmrpcivrii(ALLRMRPCIVRIInstruction * ins);
		void mooq(MOOQInstruction * ins);
		void rv(RVInstruction * ins);
		void lar(LARInstruction * ins);
		void aml(AMLInstruction * ins);
		void gml(GMLInstruction * ins);
		void sq(SQInstruction * ins);
		void emp(EMPInstruction * ins);

		/* Instruction helpers */

	private:
		Register * current_pc;
		std::vector<Register *> regs;
		std::vector<std::queue<int64_t> *> queues;
		std::queue<int64_t> * queue;
		std::vector<Instruction *> * code;
		std::vector<int64_t> * debug_queue;
		std::vector<std::vector<int64_t> *> debug_queues;
		std::vector<std::pair<int64_t, int64_t>> marklist;
};
