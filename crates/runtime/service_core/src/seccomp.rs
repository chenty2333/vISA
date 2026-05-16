use alloc::{vec, vec::Vec};

pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;
const SECCOMP_DATA_LEN: u32 = 64;
const MAX_FILTER_INSTRUCTIONS: usize = 4096;
const BPF_MEM_WORDS: usize = 16;

const BPF_CLASS_MASK: u16 = 0x07;
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_SIZE_MASK: u16 = 0x18;
const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_MODE_MASK: u16 = 0xe0;
const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;

const BPF_OP_MASK: u16 = 0xf0;
const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

const BPF_SRC_MASK: u16 = 0x08;
const BPF_RVAL_MASK: u16 = 0x18;
const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;

const BPF_MISC_MASK: u16 = 0xf8;
const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeccompInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SeccompInstruction {
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeccompFilterProgram {
    instructions: Vec<SeccompInstruction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeccompFilterChain {
    programs: Vec<SeccompFilterProgram>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeccompData {
    pub nr: u32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeccompDecision {
    Allow,
    Errno(u16),
    Kill { signal: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeccompFilterError {
    Empty,
    TooLarge,
    InvalidInstruction,
    InvalidJump,
    InvalidMemory,
    InvalidLoad,
    DivisionByZero,
    MissingReturn,
}

impl SeccompFilterProgram {
    pub fn new(instructions: Vec<SeccompInstruction>) -> Result<Self, SeccompFilterError> {
        validate_filter(&instructions)?;
        Ok(Self { instructions })
    }

    pub fn evaluate(&self, data: SeccompData) -> Result<SeccompDecision, SeccompFilterError> {
        let ret = self.evaluate_raw(data)?;
        Ok(seccomp_return_to_decision(ret))
    }

    pub fn evaluate_raw(&self, data: SeccompData) -> Result<u32, SeccompFilterError> {
        execute_filter(&self.instructions, data)
    }
}

impl SeccompFilterChain {
    pub fn new(program: SeccompFilterProgram) -> Self {
        Self { programs: vec![program] }
    }

    pub fn push(&mut self, program: SeccompFilterProgram) {
        self.programs.push(program);
    }

    pub fn evaluate(&self, data: SeccompData) -> Result<SeccompDecision, SeccompFilterError> {
        if self.programs.is_empty() {
            return Err(SeccompFilterError::Empty);
        }
        let mut selected = None::<(u8, u32)>;
        for program in self.programs.iter().rev() {
            let ret = program.evaluate_raw(data)?;
            let precedence = seccomp_action_precedence(ret);
            if selected.is_none_or(|(best, _)| precedence > best) {
                selected = Some((precedence, ret));
            }
        }
        selected.map(|(_, ret)| seccomp_return_to_decision(ret)).ok_or(SeccompFilterError::Empty)
    }
}

fn validate_filter(instructions: &[SeccompInstruction]) -> Result<(), SeccompFilterError> {
    if instructions.is_empty() {
        return Err(SeccompFilterError::Empty);
    }
    if instructions.len() > MAX_FILTER_INSTRUCTIONS {
        return Err(SeccompFilterError::TooLarge);
    }
    let last = instructions[instructions.len() - 1];
    if last.code & BPF_CLASS_MASK != BPF_RET {
        return Err(SeccompFilterError::MissingReturn);
    }
    for (pc, instruction) in instructions.iter().copied().enumerate() {
        validate_instruction(instruction, pc, instructions.len())?;
    }
    Ok(())
}

fn validate_instruction(
    instruction: SeccompInstruction,
    pc: usize,
    len: usize,
) -> Result<(), SeccompFilterError> {
    match instruction.code & BPF_CLASS_MASK {
        BPF_LD | BPF_LDX => validate_load(instruction),
        BPF_ST | BPF_STX => validate_mem_index(instruction.k),
        BPF_ALU => validate_alu(instruction),
        BPF_JMP => validate_jump(instruction, pc, len),
        BPF_RET => validate_ret(instruction),
        BPF_MISC => match instruction.code & BPF_MISC_MASK {
            BPF_TAX | BPF_TXA => Ok(()),
            _ => Err(SeccompFilterError::InvalidInstruction),
        },
        _ => Err(SeccompFilterError::InvalidInstruction),
    }
}

fn validate_load(instruction: SeccompInstruction) -> Result<(), SeccompFilterError> {
    match instruction.code & BPF_MODE_MASK {
        BPF_IMM | BPF_LEN => Ok(()),
        BPF_MEM => validate_mem_index(instruction.k),
        BPF_ABS => validate_abs_load(instruction),
        _ => Err(SeccompFilterError::InvalidLoad),
    }
}

fn validate_abs_load(instruction: SeccompInstruction) -> Result<(), SeccompFilterError> {
    let width = match instruction.code & BPF_SIZE_MASK {
        BPF_W => 4,
        BPF_H => 2,
        BPF_B => 1,
        _ => return Err(SeccompFilterError::InvalidLoad),
    };
    instruction
        .k
        .checked_add(width)
        .filter(|end| *end <= SECCOMP_DATA_LEN)
        .map(|_| ())
        .ok_or(SeccompFilterError::InvalidLoad)
}

fn validate_mem_index(index: u32) -> Result<(), SeccompFilterError> {
    if index < BPF_MEM_WORDS as u32 { Ok(()) } else { Err(SeccompFilterError::InvalidMemory) }
}

fn validate_alu(instruction: SeccompInstruction) -> Result<(), SeccompFilterError> {
    match instruction.code & BPF_OP_MASK {
        BPF_DIV | BPF_MOD if instruction.code & BPF_SRC_MASK == BPF_K && instruction.k == 0 => {
            Err(SeccompFilterError::DivisionByZero)
        }
        BPF_ADD | BPF_SUB | BPF_MUL | BPF_DIV | BPF_OR | BPF_AND | BPF_LSH | BPF_RSH | BPF_NEG
        | BPF_MOD | BPF_XOR => Ok(()),
        _ => Err(SeccompFilterError::InvalidInstruction),
    }
}

fn validate_jump(
    instruction: SeccompInstruction,
    pc: usize,
    len: usize,
) -> Result<(), SeccompFilterError> {
    match instruction.code & BPF_OP_MASK {
        BPF_JA => jump_target(pc, instruction.k, len).map(|_| ()),
        BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET => {
            jump_target(pc, instruction.jt as u32, len)?;
            jump_target(pc, instruction.jf as u32, len).map(|_| ())
        }
        _ => Err(SeccompFilterError::InvalidJump),
    }
}

fn validate_ret(instruction: SeccompInstruction) -> Result<(), SeccompFilterError> {
    match instruction.code & BPF_RVAL_MASK {
        BPF_K | BPF_A => Ok(()),
        _ => Err(SeccompFilterError::InvalidInstruction),
    }
}

fn jump_target(pc: usize, offset: u32, len: usize) -> Result<usize, SeccompFilterError> {
    let target = pc
        .checked_add(1)
        .and_then(|base| base.checked_add(offset as usize))
        .ok_or(SeccompFilterError::InvalidJump)?;
    if target < len { Ok(target) } else { Err(SeccompFilterError::InvalidJump) }
}

fn execute_filter(
    instructions: &[SeccompInstruction],
    data: SeccompData,
) -> Result<u32, SeccompFilterError> {
    let mut pc = 0usize;
    let mut a = 0u32;
    let mut x = 0u32;
    let mut mem = [0u32; BPF_MEM_WORDS];

    while pc < instructions.len() {
        let instruction = instructions[pc];
        match instruction.code & BPF_CLASS_MASK {
            BPF_LD => {
                a = load_value(instruction, x, &mem, data)?;
                pc += 1;
            }
            BPF_LDX => {
                x = load_value(instruction, x, &mem, data)?;
                pc += 1;
            }
            BPF_ST => {
                mem[mem_index(instruction.k)?] = a;
                pc += 1;
            }
            BPF_STX => {
                mem[mem_index(instruction.k)?] = x;
                pc += 1;
            }
            BPF_ALU => {
                a = alu_value(instruction, a, x)?;
                pc += 1;
            }
            BPF_JMP => {
                pc = next_pc(instruction, pc, a, x, instructions.len())?;
            }
            BPF_RET => {
                return match instruction.code & BPF_RVAL_MASK {
                    BPF_K => Ok(instruction.k),
                    BPF_A => Ok(a),
                    _ => Err(SeccompFilterError::InvalidInstruction),
                };
            }
            BPF_MISC => {
                match instruction.code & BPF_MISC_MASK {
                    BPF_TAX => x = a,
                    BPF_TXA => a = x,
                    _ => return Err(SeccompFilterError::InvalidInstruction),
                }
                pc += 1;
            }
            _ => return Err(SeccompFilterError::InvalidInstruction),
        }
    }

    Err(SeccompFilterError::MissingReturn)
}

fn load_value(
    instruction: SeccompInstruction,
    _x: u32,
    mem: &[u32; BPF_MEM_WORDS],
    data: SeccompData,
) -> Result<u32, SeccompFilterError> {
    match instruction.code & BPF_MODE_MASK {
        BPF_IMM => Ok(instruction.k),
        BPF_MEM => Ok(mem[mem_index(instruction.k)?]),
        BPF_LEN => Ok(SECCOMP_DATA_LEN),
        BPF_ABS => load_seccomp_data(data, instruction.k, instruction.code & BPF_SIZE_MASK),
        _ => Err(SeccompFilterError::InvalidLoad),
    }
}

fn load_seccomp_data(data: SeccompData, offset: u32, size: u16) -> Result<u32, SeccompFilterError> {
    let mut bytes = [0u8; SECCOMP_DATA_LEN as usize];
    bytes[0..4].copy_from_slice(&data.nr.to_le_bytes());
    bytes[4..8].copy_from_slice(&data.arch.to_le_bytes());
    bytes[8..16].copy_from_slice(&data.instruction_pointer.to_le_bytes());
    for (index, arg) in data.args.iter().copied().enumerate() {
        let start = 16 + index * 8;
        bytes[start..start + 8].copy_from_slice(&arg.to_le_bytes());
    }

    let offset = offset as usize;
    match size {
        BPF_W => {
            let end = offset.checked_add(4).ok_or(SeccompFilterError::InvalidLoad)?;
            if end > bytes.len() {
                return Err(SeccompFilterError::InvalidLoad);
            }
            Ok(u32::from_le_bytes(
                bytes[offset..end].try_into().map_err(|_| SeccompFilterError::InvalidLoad)?,
            ))
        }
        BPF_H => {
            let end = offset.checked_add(2).ok_or(SeccompFilterError::InvalidLoad)?;
            if end > bytes.len() {
                return Err(SeccompFilterError::InvalidLoad);
            }
            Ok(u16::from_le_bytes(
                bytes[offset..end].try_into().map_err(|_| SeccompFilterError::InvalidLoad)?,
            ) as u32)
        }
        BPF_B => {
            if offset >= bytes.len() {
                return Err(SeccompFilterError::InvalidLoad);
            }
            Ok(bytes[offset] as u32)
        }
        _ => Err(SeccompFilterError::InvalidLoad),
    }
}

fn mem_index(index: u32) -> Result<usize, SeccompFilterError> {
    if index < BPF_MEM_WORDS as u32 {
        Ok(index as usize)
    } else {
        Err(SeccompFilterError::InvalidMemory)
    }
}

fn alu_value(instruction: SeccompInstruction, a: u32, x: u32) -> Result<u32, SeccompFilterError> {
    let rhs = match instruction.code & BPF_SRC_MASK {
        BPF_K => instruction.k,
        BPF_X => x,
        _ => return Err(SeccompFilterError::InvalidInstruction),
    };
    match instruction.code & BPF_OP_MASK {
        BPF_ADD => Ok(a.wrapping_add(rhs)),
        BPF_SUB => Ok(a.wrapping_sub(rhs)),
        BPF_MUL => Ok(a.wrapping_mul(rhs)),
        BPF_DIV => {
            if rhs == 0 {
                Err(SeccompFilterError::DivisionByZero)
            } else {
                Ok(a / rhs)
            }
        }
        BPF_OR => Ok(a | rhs),
        BPF_AND => Ok(a & rhs),
        BPF_LSH => Ok(a.wrapping_shl(rhs)),
        BPF_RSH => Ok(a.wrapping_shr(rhs)),
        BPF_NEG => Ok(a.wrapping_neg()),
        BPF_MOD => {
            if rhs == 0 {
                Err(SeccompFilterError::DivisionByZero)
            } else {
                Ok(a % rhs)
            }
        }
        BPF_XOR => Ok(a ^ rhs),
        _ => Err(SeccompFilterError::InvalidInstruction),
    }
}

fn next_pc(
    instruction: SeccompInstruction,
    pc: usize,
    a: u32,
    x: u32,
    len: usize,
) -> Result<usize, SeccompFilterError> {
    match instruction.code & BPF_OP_MASK {
        BPF_JA => jump_target(pc, instruction.k, len),
        BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET => {
            let rhs = match instruction.code & BPF_SRC_MASK {
                BPF_K => instruction.k,
                BPF_X => x,
                _ => return Err(SeccompFilterError::InvalidInstruction),
            };
            let matches = match instruction.code & BPF_OP_MASK {
                BPF_JEQ => a == rhs,
                BPF_JGT => a > rhs,
                BPF_JGE => a >= rhs,
                BPF_JSET => a & rhs != 0,
                _ => false,
            };
            let offset = if matches { instruction.jt } else { instruction.jf };
            jump_target(pc, offset as u32, len)
        }
        _ => Err(SeccompFilterError::InvalidJump),
    }
}

fn seccomp_return_to_decision(ret: u32) -> SeccompDecision {
    match ret & SECCOMP_RET_ACTION_FULL {
        SECCOMP_RET_ALLOW => SeccompDecision::Allow,
        SECCOMP_RET_LOG => SeccompDecision::Allow,
        SECCOMP_RET_ERRNO => SeccompDecision::Errno((ret & SECCOMP_RET_DATA) as u16),
        SECCOMP_RET_KILL_PROCESS | SECCOMP_RET_KILL_THREAD => SeccompDecision::Kill { signal: 31 },
        SECCOMP_RET_TRAP | SECCOMP_RET_TRACE | SECCOMP_RET_USER_NOTIF => {
            SeccompDecision::Kill { signal: 31 }
        }
        _ => SeccompDecision::Kill { signal: 31 },
    }
}

fn seccomp_action_precedence(ret: u32) -> u8 {
    match ret & SECCOMP_RET_ACTION_FULL {
        SECCOMP_RET_KILL_PROCESS => 8,
        SECCOMP_RET_KILL_THREAD => 7,
        SECCOMP_RET_TRAP => 6,
        SECCOMP_RET_ERRNO => 5,
        SECCOMP_RET_USER_NOTIF => 4,
        SECCOMP_RET_TRACE => 3,
        SECCOMP_RET_LOG => 2,
        SECCOMP_RET_ALLOW => 1,
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const BPF_LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
    const BPF_JMP_JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
    const BPF_ALU_DIV_K: u16 = BPF_ALU | BPF_DIV | BPF_K;
    const BPF_RET_K: u16 = BPF_RET | BPF_K;
    const BPF_RET_A: u16 = BPF_RET | BPF_A;

    fn data(syscall: u32) -> SeccompData {
        SeccompData {
            nr: syscall,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0x401000,
            args: [0; 6],
        }
    }

    #[test]
    fn filter_allows_matching_syscall_and_errno_for_other_syscalls() {
        let program = SeccompFilterProgram::new(vec![
            SeccompInstruction::new(BPF_LD_W_ABS, 0, 0, 0),
            SeccompInstruction::new(BPF_JMP_JEQ_K, 0, 1, 1),
            SeccompInstruction::new(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            SeccompInstruction::new(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 13),
        ])
        .expect("valid filter");

        assert_eq!(program.evaluate(data(1)), Ok(SeccompDecision::Allow));
        assert_eq!(program.evaluate(data(2)), Ok(SeccompDecision::Errno(13)));
    }

    #[test]
    fn filter_can_gate_on_arch_field() {
        let program = SeccompFilterProgram::new(vec![
            SeccompInstruction::new(BPF_LD_W_ABS, 0, 0, 4),
            SeccompInstruction::new(BPF_JMP_JEQ_K, 0, 1, AUDIT_ARCH_X86_64),
            SeccompInstruction::new(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            SeccompInstruction::new(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        ])
        .expect("valid filter");

        assert_eq!(program.evaluate(data(1)), Ok(SeccompDecision::Allow));
        assert_eq!(
            program.evaluate(SeccompData { arch: 0, ..data(1) }),
            Ok(SeccompDecision::Kill { signal: 31 })
        );
    }

    #[test]
    fn filter_supports_returning_accumulator_value() {
        let program = SeccompFilterProgram::new(vec![
            SeccompInstruction::new(BPF_LD | BPF_W | BPF_IMM, 0, 0, SECCOMP_RET_LOG),
            SeccompInstruction::new(BPF_RET_A, 0, 0, 0),
        ])
        .expect("valid ret-a filter");

        assert_eq!(program.evaluate(data(1)), Ok(SeccompDecision::Allow));
    }

    #[test]
    fn validator_rejects_out_of_bounds_jumps_and_missing_return() {
        assert_eq!(
            SeccompFilterProgram::new(vec![SeccompInstruction::new(BPF_JMP | BPF_JA, 0, 0, 1)]),
            Err(SeccompFilterError::MissingReturn)
        );
        assert_eq!(
            SeccompFilterProgram::new(vec![
                SeccompInstruction::new(BPF_JMP | BPF_JA, 0, 0, 1),
                SeccompInstruction::new(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            ]),
            Err(SeccompFilterError::InvalidJump)
        );
    }

    #[test]
    fn validator_rejects_constant_division_by_zero() {
        assert_eq!(
            SeccompFilterProgram::new(vec![
                SeccompInstruction::new(BPF_LD | BPF_W | BPF_IMM, 0, 0, 1),
                SeccompInstruction::new(BPF_ALU_DIV_K, 0, 0, 0),
                SeccompInstruction::new(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            ]),
            Err(SeccompFilterError::DivisionByZero)
        );
    }

    #[test]
    fn chain_uses_highest_precedence_action() {
        let allow = SeccompFilterProgram::new(vec![SeccompInstruction::new(
            BPF_RET_K,
            0,
            0,
            SECCOMP_RET_ALLOW,
        )])
        .expect("allow filter");
        let errno = SeccompFilterProgram::new(vec![SeccompInstruction::new(
            BPF_RET_K,
            0,
            0,
            SECCOMP_RET_ERRNO | 22,
        )])
        .expect("errno filter");
        let kill = SeccompFilterProgram::new(vec![SeccompInstruction::new(
            BPF_RET_K,
            0,
            0,
            SECCOMP_RET_KILL_PROCESS,
        )])
        .expect("kill filter");

        let mut chain = SeccompFilterChain::new(allow);
        chain.push(errno);
        assert_eq!(chain.evaluate(data(1)), Ok(SeccompDecision::Errno(22)));
        chain.push(kill);
        assert_eq!(chain.evaluate(data(1)), Ok(SeccompDecision::Kill { signal: 31 }));
    }

    #[test]
    fn chain_keeps_newest_data_for_same_action_precedence() {
        let first = SeccompFilterProgram::new(vec![SeccompInstruction::new(
            BPF_RET_K,
            0,
            0,
            SECCOMP_RET_ERRNO | 13,
        )])
        .expect("first errno filter");
        let second = SeccompFilterProgram::new(vec![SeccompInstruction::new(
            BPF_RET_K,
            0,
            0,
            SECCOMP_RET_ERRNO | 22,
        )])
        .expect("second errno filter");

        let mut chain = SeccompFilterChain::new(first);
        chain.push(second);

        assert_eq!(chain.evaluate(data(1)), Ok(SeccompDecision::Errno(22)));
    }
}
