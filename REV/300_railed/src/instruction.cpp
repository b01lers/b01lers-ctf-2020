#include "instruction.hpp"


Instruction::Instruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

Instruction::~Instruction() {
	delete this->imm;
	/* Don't touch the regs here, they're deleted when context is */
}

MPCInstruction::MPCInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

MPCInstruction::~MPCInstruction() {
}

HCFInstruction::HCFInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

HCFInstruction::~HCFInstruction() {
	/* No need to delete ctx (in fact yeah DON'T) */
}

ENQInstruction::ENQInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

ENQInstruction::~ENQInstruction() {
	/* No need to delete ctx (in fact yeah DON'T) */
}

DEQInstruction::DEQInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}


DEQInstruction::~DEQInstruction() {

}

JSZInstruction::JSZInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

JSZInstruction::~JSZInstruction() {

}

ALLRMRPCIVRIInstruction::ALLRMRPCIVRIInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

ALLRMRPCIVRIInstruction::~ALLRMRPCIVRIInstruction() {
}

MOOQInstruction::MOOQInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

MOOQInstruction::~MOOQInstruction() {
}

RVInstruction::RVInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

RVInstruction::~RVInstruction() {
}

LARInstruction::LARInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

LARInstruction::~LARInstruction() {
}

AMLInstruction::AMLInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

AMLInstruction::~AMLInstruction() {
}

GMLInstruction::GMLInstruction(int64_t * imm) {
	this->imm = imm;
	this->regs = std::vector<Register *>();
}

GMLInstruction::GMLInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

GMLInstruction::~GMLInstruction() {
}

SQInstruction::SQInstruction(int64_t * imm) {
	this->imm = imm;
	this->regs = std::vector<Register *>();
}

SQInstruction::SQInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

SQInstruction::~SQInstruction() {
}

EMPInstruction::EMPInstruction(void) {
	this->imm = NULL;
	this->regs = std::vector<Register *>();
}

EMPInstruction::~EMPInstruction() {
}
