#include "context.hpp"

Context::Context(std::vector<Instruction *> * code) {
	this->regs.push_back(new Register("ra", 0, true));
	this->current_pc = this->regs.front();
	for (std::string name : {"rb", "rc", "rd", "re"}) {
		this->regs.push_back(new Register(name, 0, false));
	}
	this->queue = new std::queue<int64_t>();
	this->queues.push_back(this->queue);
	this->debug_queue = new std::vector<int64_t>();
	this->debug_queues.push_back(this->debug_queue);
	this->code = code;
}

Context::Context() {
	this->regs.push_back(new Register("ra", 0, true));
	this->current_pc = this->regs.front();
	for (std::string name : {"rb", "rc", "rd", "re"}) {
		this->regs.push_back(new Register(name, 0, false));
	}
	this->queue = new std::queue<int64_t>();
	this->queues.push_back(this->queue);
	this->debug_queue = new std::vector<int64_t>();
	this->debug_queues.push_back(this->debug_queue);
	this->code = new std::vector<Instruction *>();
}

void Context::add_instruction(Instruction * ins) {
	this->code->push_back(ins);
}

Register * Context::get_reg(std::string regname) {
	for (Register * r : this->regs) {
		if (r->name == regname) {
			return r;
		}
	}
	return NULL;
}

void printsep(void) {
	struct winsize size;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
	size_t cols = size.ws_col;
	for (size_t i = 0; i < cols; i++) {
		std::cout << "*";
	}
	std::cout << std::endl;
}

void Context::printstate(void) {
#ifdef DEBUG
	printsep();
	for (Register * r : this->regs) {
		std::cout << "name: " << r->name << " value: " << std::bitset<64>(r->value) << " " << std::setfill('0') << std::hex << r->value << " pc: 0x" << std::setfill('0') << std::setw(16) << std::hex << r->pc << std::endl;
	}
	for (auto q : this->debug_queues) {
		std::cout << "QUEUE: " << std::endl;
		for (int64_t i : *q) {
			std::cout << " 0x" << std::hex << i << "--> ";
		}
		std::cout << std::endl;
	}
	std::cout << "MARKLIST: " << std::endl;
	for (std::pair<int64_t, int64_t> p : this->marklist) {
		std::cout << "{" << p.first << "," << p.second << "},";
	}
	std::cout << std::endl;
	printsep();
#endif
}

void Context::update_reg(Register * r, int64_t value) {
	r->value = value;
}

void Context::enqueue(Register * r) {
	this->queue->push(r->value);
	this->debug_queue->insert(this->debug_queue->begin(), r->value);
	r->value = 0;
}

void Context::enqueue(int64_t value) {
	this->queue->push(value);
	this->debug_queue->insert(this->debug_queue->begin(), value);
}

void Context::dequeue(void) {
	this->queue->pop();
	this->debug_queue->pop_back();
}

void Context::dequeue(Register * r) {
	r->value = this->queue->front();
	this->queue->pop();
	this->debug_queue->pop_back();
}

int64_t Context::queue_front(void) {
	return this->queue->front();
}

size_t Context::queue_size(void) {
	return this->queue->size();
}

void Context::halt(void) {
	while (true) {
		;
	}
}

Context::~Context() {
	for (Register * r : this->regs) {
		delete r;
	}
	for (Instruction * i : *this->code) {
		delete i;
	}
	delete this->code;
}

void Context::execute(Instruction * i) {
	this->printstate();
	if (dynamic_cast<MPCInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "MPC" << std::endl;
#endif
		this->mpc((MPCInstruction *) i);
	} else if (dynamic_cast<HCFInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "HCF" << std::endl;
#endif
		this->hcf((HCFInstruction *) i);
	} else if (dynamic_cast<ENQInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "ENQ" << std::endl;
#endif
		this->enq((ENQInstruction *) i);
	} else if (dynamic_cast<DEQInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "DEQ" << std::endl;
#endif
		this->deq((DEQInstruction *) i);
	} else if (dynamic_cast<JSZInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "JSZ" << std::endl;
#endif
		this->jsz((JSZInstruction *) i);
	} else if (dynamic_cast<ALLRMRPCIVRIInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "ALLRMRPCIVRI" << std::endl;
#endif
		this->allrmrpcivrii((ALLRMRPCIVRIInstruction *) i);
	} else if (dynamic_cast<MOOQInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "MOOQ" << std::endl;
#endif
		this->mooq((MOOQInstruction *) i);
	} else if (dynamic_cast<RVInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "RV" << std::endl;
#endif
		this->rv((RVInstruction *) i);
	} else if (dynamic_cast<LARInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "LAR" << std::endl;
#endif
		this->lar((LARInstruction *) i);
	} else if (dynamic_cast<AMLInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "AML" << std::endl;
#endif
		this->aml((AMLInstruction *) i);
	} else if (dynamic_cast<GMLInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "GML" << std::endl;
#endif
		this->gml((GMLInstruction *) i);
	} else if (dynamic_cast<SQInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "SQ" << std::endl;
#endif
		this->sq((SQInstruction *) i);
	} else if (dynamic_cast<EMPInstruction *>(i)) {
#ifdef DEBUG
		std::cout << "EMP" << std::endl;
#endif
		this->emp((EMPInstruction *) i);
	}
}

void Context::run(void) {
	while(this->current_pc->value >= 0 && this->current_pc->value < (int64_t) this->code->size() ) {
		this->execute(this->code->at(this->current_pc->value));
		this->current_pc->value++;
	}
	std::cout << "Exiting." << std::endl;
	this->printstate();
}

void Context::mpc(MPCInstruction * ins) {
	this->current_pc->pc = false;
	this->current_pc = ins->regs.at(0);
	this->current_pc->pc = true;
	if (ins->imm != NULL) {
		this->current_pc->value += *ins->imm;
	}
	return;
}

void Context::hcf(HCFInstruction * ins) {
	for (Register * r : ins->regs) {
		std::cout << "0x" << std::hex << r->value << std::endl;
	}
	this->halt();
	return;
}

void Context::enq(ENQInstruction * ins) {
	if (ins->imm == NULL) {
		this->enqueue(ins->regs.at(0));
	} else {
		this->enqueue(ins->regs.at(0)->value);
	}
}

void Context::deq(DEQInstruction * ins) {
	if (this->queue_size() > 0) {
		if (ins->regs.empty()) {
			this->dequeue();
		} else {
			this->dequeue(ins->regs.at(0));
			if (ins->imm != NULL) {
				ins->regs.at(0)->value += *ins->imm;
			}
		}
	}
}

void Context::jsz(JSZInstruction * ins) {
	std::bitset<64> a(ins->regs.at(0)->value);
	std::bitset<64> b(ins->regs.at(1)->value);
	if (a.count() == b.count()) {
		int64_t target = ins->regs.at(2)->value;
		this->current_pc->value = this->current_pc->value + target;
	} else {
		return;
	}
}

void Context::allrmrpcivrii(ALLRMRPCIVRIInstruction * ins) {
	std::bitset<64> a(ins->regs.at(0)->value);
	if (ins->imm != NULL && ins->imm1 != NULL) {
		for (int64_t i = *ins->imm; i < *ins->imm1; i++) {
			a.flip(i);
		}
	} else {
		for (int64_t i = ins->regs.at(1)->value; i < ins->regs.at(2)->value; i++) {
			a.flip(i);
		}
	}
	ins->regs.at(0)->value = a.to_ullong();
}

void Context::mooq(__attribute__((unused)) MOOQInstruction * ins) {
	std::vector<int64_t> holder;
	for (unsigned int i = 0; i < (this->queue_size() / 2) + 1; i++) {
		holder.push_back(this->queue_front());
		this->dequeue();
	}
	for (auto it = holder.begin(); it != holder.end(); it++) {
		this->enqueue(*it);
	}
}

void Context::rv(RVInstruction * ins) {
	std::bitset<64> a(ins->regs.at(0)->value);
	std::bitset<64> b(ins->regs.at(1)->value);
	std::bitset<1> tmp;

	if (ins->imm == NULL) {
		for (unsigned i = 0; i < a.size(); i++) {
			if (b.test(i)) {
				a.set(i, b.test(i));
			}
		}
	} else {
		int64_t imm_val = *ins->imm;
		std::bitset<32> upper(imm_val >> 32);
		std::bitset<32> lower(imm_val);
		// Flip even bits using lower as a mask
#ifdef DEBUG
		std::cout << "UPPER: " << upper << std::endl;
		std::cout << "LOWER: " << lower << std::endl;
#endif
		for (int i = 0; i < 32; i++) {
			if (upper.none() && lower.test(i)) {
#ifdef DEBUG
				std::cout << "SETTING EVEN BIT: << " << i << std::endl;
#endif
				tmp.set(0, a.test(i * 2));
				a.set(i * 2, b.test(i * 2));
				b.set(i * 2, tmp.test(0));
			} else if (lower.none() && upper.test(i)) {
				tmp.set(0, a.test((2 * i) + 1));
				a.set((i * 2) + 1, b.test((i * 2) + 1));
				b.set((i * 2) + 1, tmp.test(0));
			}
		}
	}
	ins->regs.at(0)->value = a.to_ullong();
	ins->regs.at(1)->value = b.to_ullong();
}

void Context::lar(LARInstruction * ins) {
	ins->regs.at(0)->value = *ins->imm;
	for (Register * r : this->regs) {
		if (r != ins->regs.at(0) && r != this->current_pc) {
			this->mpc(new MPCInstruction(new int64_t(0), r));
		}
	}
}

void Context::aml(AMLInstruction * ins) {
	std::pair<int64_t, int64_t> p;
	if (ins->imm == NULL && ins->regs.size() == 0) {
		p = std::pair<int64_t, int64_t>(this->current_pc->value, 1);
	} else if (ins->imm == NULL) {
		p = std::pair<int64_t, int64_t>(this->current_pc->value, ins->regs.at(0)->value);

	} else if (ins->regs.size() == 0) {
		p = std::pair<int64_t, int64_t>(this->current_pc->value, *ins->imm);
	}
	this->marklist.insert(this->marklist.begin(), p);
}

void Context::gml(GMLInstruction * ins) {
	if (ins->imm == NULL) {
		if (this->marklist.size() > ins->regs.at(0)->value) {
			if (this->marklist.at(ins->regs.at(0)->value).second-- > 0) {
				this->current_pc->value = this->marklist.at(ins->regs.at(0)->value).first;
			}
		}
	} else {
		if (this->marklist.size() > *ins->imm) {
			if (this->marklist.at(*ins->imm).second-- > 0) {
				this->current_pc->value = this->marklist.at(*ins->imm).first;
			}
		}
	}
}

void Context::sq(SQInstruction * ins) {
	if (ins->imm == NULL) {
		if (this->queues.size() < (unsigned int) ins->regs.at(0)->value + 1) {
			for (unsigned int i = 0; i < ins->regs.at(0)->value + 1 - this->queues.size(); i++) {
				this->queues.push_back(new std::queue<int64_t>());
				this->debug_queues.push_back(new std::vector<int64_t>());
			}
		}
		this->queue = this->queues.at(ins->regs.at(0)->value);
		this->debug_queue = this->debug_queues.at(ins->regs.at(0)->value);
	} else {
		if (this->queues.size() < (unsigned int) *ins->imm + 1) {
			for (unsigned int i = 0; i < *ins->imm + 1 - this->queues.size(); i++) {
				this->queues.push_back(new std::queue<int64_t>());
				this->debug_queues.push_back(new std::vector<int64_t>());
			}
		}
		this->queue = this->queues.at(*ins->imm);
		this->debug_queue = this->debug_queues.at(*ins->imm);
	}
}

void Context::emp(EMPInstruction * ins) {
	std::bitset<64> a(ins->regs.at(0)->value);
	std::bitset<64> b(ins->regs.at(1)->value);
	for (unsigned int apos = *ins->imm, bpos = 0; apos > 0; apos--, bpos++) {
		a.set(apos, b.test(bpos));
	}
	ins->regs.at(0)->value = a.to_ullong();
}