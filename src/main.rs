#[cfg(not(any(target_os = "linux", target_os = "android")))]
compile_error!("This library only supports linux and android !");

extern crate goblin;
extern crate nix;

use goblin::elf::header::ELFMAG;
use goblin::elf::{program_header, Elf, SectionHeader};
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{IoSliceMut, Seek, SeekFrom};
use std::{fs::File, io::Read, path::Path};

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct VMA {
    begin: u64,
    end: u64,
    perm: [char; 4],
    offset: u64,
    inode: u32,
    filename: String,
}

fn list_vma_vec(pid: i32) -> Result<Vec<VMA>, String> {
    let maps_path = format!("/proc/{}/maps", pid);

    // 读取进程的内存映射信息
    let mut maps_file = match File::open(&Path::new(&maps_path)) {
        Ok(file) => file,
        Err(err) => return Err(format!("Failed to open {}: {}", maps_path, err)),
    };

    let mut content = String::new();
    if let Err(err) = maps_file.read_to_string(&mut content) {
        return Err(format!("Failed to read {}: {}", maps_path, err));
    }

    // 解析内存映射以及文件名
    let vma_infos: Vec<VMA> = content.lines().filter_map(parse_vma_line).collect();

    Ok(vma_infos)
}

fn parse_vma_line(line: &str) -> Option<VMA> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 6 {
        let mapped_range = parts[0];
        let (begin_addr, end_addr) = mapped_range.split_once('-')?;
        let begin = u64::from_str_radix(begin_addr, 16).ok()?;
        let end = u64::from_str_radix(end_addr, 16).ok()?;
        let perm: [char; 4] = extract_vma_permissions(parts[1])?;
        let offset = u64::from_str_radix(parts[2], 16).ok()?;
        let inode: u32 = parts[4].parse().ok()?;
        let filename = parts[5];

        Some(VMA {
            begin,
            end,
            perm,
            offset,
            inode,
            filename: String::from(filename),
        })
    } else {
        None
    }
}

fn extract_vma_permissions(permission: &str) -> Option<[char; 4]> {
    let perm: Vec<char> = permission.chars().take(4).collect();
    perm.try_into().ok()
}

#[allow(dead_code)]
struct DiffBlock {
    file_offset: u64,
    len: usize,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]

struct DynamicLibrary {
    pid: i32,
    base_addr: u64,
    bias_addr: u64,
    filename: String,
    vma_list: Vec<VMA>,

    x_segment_start: u64,
    x_segment_end: u64,
    scope_range_list: Vec<SectionHeader>,
}

impl DynamicLibrary {
    pub fn new(pid: i32, filename: String, vma_list: Vec<VMA>) -> Result<Self, &'static str> {
        let elf_bytes = std::fs::read(&filename).unwrap();
        let elf = Elf::parse(&elf_bytes).unwrap();
        let mut x_segment_start = 0;
        let mut x_segment_end = 0;
        for phdr in elf.program_headers {
            if phdr.p_type == program_header::PT_LOAD && (phdr.p_flags & program_header::PF_X != 0)
            {
                x_segment_start = phdr.p_vaddr;
                x_segment_end = phdr.p_vaddr + phdr.p_memsz;
            }
        }
        // 取出 ".text" 和 "il2cpp" section 的范围
        let mut scope_list: Vec<SectionHeader> = Vec::new();
        for section_header in elf.section_headers {
            if let Some(section_name) = elf.shdr_strtab.get_at(section_header.sh_name) {
                if section_name == ".text" || section_name == "il2cpp" {
                    scope_list.push(section_header.clone());
                }
            }
        }

        let mut likely_headers: Vec<VMA> = Vec::new();
        // 根据 ELF Header 特征获取疑似 Header 的 VMA
        for vma in &vma_list {
            if let Ok(mem) = DynamicLibrary::read_process_memory(pid, vma.begin, 64) {
                // 判断头
                if mem.get(0..4) == Some(&ELFMAG[..]) {
                    likely_headers.push(vma.clone());
                }
            }
        }
        if likely_headers.len() == 0 {
            return Err("不存在 ELF Header");
        }

        let mut base_addr: u64 = u64::MAX;
        let mut bias_addr: u64 = u64::MAX;

        // 检查是否已正确映射第一个可执行 PT_LOAD Segment
        for vma in likely_headers {
            let start_addr = vma.begin + x_segment_start;
            let end_addr = vma.begin + x_segment_end;
            let mut found_start = false;
            let mut found_end = false;

            for v in &vma_list {
                if start_addr >= v.begin && start_addr < v.end {
                    found_start = true;
                }
                if end_addr >= v.begin && end_addr < v.end {
                    found_end = true;
                }
            }

            if found_start && found_end {
                base_addr = vma.begin;
                bias_addr = start_addr;
            }
        }

        if base_addr == u64::MAX {
            return Err("未初始化的动态库");
        }

        Ok(Self {
            pid: pid,
            base_addr: base_addr,
            bias_addr: bias_addr,
            filename: filename,
            vma_list: vma_list,
            x_segment_start: x_segment_start,
            x_segment_end: x_segment_end,
            scope_range_list: scope_list,
        })
    }

    // 验证可执行代码内存
    pub fn verif_text_memory(&self) -> Option<Vec<DiffBlock>> {
        // 对比 `il2cpp` 内存 和 文件，如果存在 "il2cpp" section，则包含 `il2cpp` 的内存范围

        // 保存
        let mut diff_blocks: Vec<DiffBlock> = Vec::new();
        let mut file = File::open(Path::new(&self.filename)).unwrap();
        for scope in &self.scope_range_list {
            // 读文件
            file.seek(SeekFrom::Start(scope.sh_offset)).unwrap();
            let mut file_block = vec![0; scope.sh_size as usize];
            file.read_exact(&mut file_block).unwrap();

            let mem_block: Vec<u8> = DynamicLibrary::read_process_memory(
                self.pid,
                self.base_addr + scope.sh_addr,
                scope.sh_size as u32,
            )
            .unwrap();
            let diff = DynamicLibrary::find_differences(
                scope.sh_offset,
                file_block.as_slice(),
                mem_block.as_slice(),
            );
            if diff.len() != 0 {
                diff_blocks.extend(diff);
            }
        }
        if diff_blocks.len() > 0 {
            return Some(diff_blocks);
        }

        return None;
    }

    fn find_differences(base: u64, file_block: &[u8], mem_block: &[u8]) -> Vec<DiffBlock> {
        let mut differences = Vec::new();
        let mut current_offset = 0;
        let mut current_length = 0;

        let mut diff_bytes: Vec<u8> = Vec::new();

        for i in 0..file_block.len() {
            if file_block[i] != mem_block[i] {
                diff_bytes.push(mem_block[i]);
                if current_length == 0 {
                    current_offset = i as u64;
                }
                current_length += 1;
            } else if current_length > 0 {
                differences.push(DiffBlock {
                    file_offset: base + current_offset,
                    len: current_length,
                    bytes: diff_bytes,
                });
                diff_bytes = Vec::new();
                current_length = 0;
            }
        }

        if current_length > 0 {
            differences.push(DiffBlock {
                file_offset: base + current_offset,
                len: current_length,
                bytes: diff_bytes,
            });
        }

        differences
    }

    fn read_process_memory(pid: i32, base: u64, len: u32) -> Result<Vec<u8>, String> {
        let remote_iov = RemoteIoVec {
            base: base as usize,
            len: len as usize,
        };

        let mut buffer: Vec<u8> = Vec::with_capacity(len as usize);
        for _ in 0..len {
            buffer.push(0);
        }

        let buf: &mut [u8] = buffer.as_mut_slice();
        let local_iov = IoSliceMut::new(buf);

        let result = process_vm_readv(Pid::from_raw(pid), &mut [local_iov], &[remote_iov]);
        match result {
            Ok(_data) => {
                return Ok(buffer);
            }
            Err(_errno) => {
                return Err("读取内存失败".to_string());
            }
        }
    }
}

fn main() {
    let pid = std::process::id() as i32;
    // 读取内存布局
    let vma_infos = list_vma_vec(pid).expect("读取内存失败");
    // 使用 [filename : VMA] 的形式，重新组织 vma_infos，整理出每一个文件对应的映射内存信息
    let mut filemaps: HashMap<String, Vec<VMA>> = HashMap::new();
    for vma in &vma_infos {
        if vma.inode == 0 {
            continue;
        }
        filemaps
            .entry(vma.filename.clone())
            .or_insert_with(Vec::new)
            .push(vma.clone());
    }
    // 
    for (filename, vma_list) in filemaps {
        // FIXME 跳过非 ELF 文件
        let dynlib = DynamicLibrary::new(pid, filename.clone(), vma_list).unwrap();
        if let Some(_diff_blocks) = dynlib.verif_text_memory() {
            println!("found memory broken in '{}'", dynlib.filename);
        }
    }
}
