//! Process management syscalls
use core::mem::size_of;

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE},
    mm::{translated_byte_buffer, MapPermission, VirtAddr},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next, task_manager_lock, TaskStatus,
    },
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let write_val =
        translated_byte_buffer(current_user_token(), ts as *const u8, size_of::<TimeVal>());
    let ptr = write_val[0].as_ptr() as *mut u8 as *mut TimeVal;
    unsafe {
        *ptr = time_val;
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    let write_val =
        translated_byte_buffer(current_user_token(), ti as *const u8, size_of::<TimeVal>());
    let ptr = write_val[0].as_ptr() as *mut u8 as *mut TaskInfo;
    let mut lock = task_manager_lock();
    let current_task = lock.current_task;
    let tcb = &mut lock.tasks[current_task];
    unsafe {
        (*ptr).syscall_times = tcb.syscall_times;
        (*ptr).status = tcb.task_status;
        let us = get_time_us() - tcb.start_running_time;
        let tv = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
        let time = ((tv.sec & 0xffff) * 1000 + tv.usec / 1000) as isize;
        (*ptr).time = time as usize;
    }
    0
}

bitflags! {
    pub struct PORT: usize{
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, raw_port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    let permission = MapPermission::from_bits((raw_port << 1) as u8);
    if permission.is_none() {
        return -1;
    }
    let permission = permission.unwrap();
    if permission.is_empty() || permission.contains(MapPermission::U) {
        return -1;
    }
    let mut lock = task_manager_lock();
    let current_task = lock.current_task;
    let tcb = &mut lock.tasks[current_task];
    let memory_set = &mut tcb.memory_set;

    match memory_set.insert_framed_area(
        VirtAddr(start),
        VirtAddr(start + len),
        permission.union(MapPermission::U),
    ) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    let mut lock = task_manager_lock();
    let current_task = lock.current_task;
    let tcb = &mut lock.tasks[current_task];
    let memory_set = &mut tcb.memory_set;
    match memory_set.unmap(start, len) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
