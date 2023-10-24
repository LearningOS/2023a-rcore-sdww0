//! Process management syscalls
use crate::{
    config::MAX_SYSCALL_NUM,
    task::{
        exit_current_and_run_next, suspend_current_and_run_next, task_manager_lock, TaskStatus,
    },
    timer::get_time_us,
};

/// Time val
#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    /// second
    pub sec: usize,
    /// usecond
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    pub status: TaskStatus,
    /// The numbers of syscall called by task
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    pub time: usize,
}

impl Default for TaskInfo {
    fn default() -> Self {
        Self {
            status: TaskStatus::Ready,
            syscall_times: [0;MAX_SYSCALL_NUM],
            time: Default::default(),
        }
    }
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// get time with second and microsecond
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    unsafe {
        *ts = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    let mut lock = task_manager_lock();
    let current_task = lock.current_task;
    let tcb = &mut lock.tasks[current_task];
    unsafe {
        (*ti).syscall_times = tcb.task_info.syscall_times;
        (*ti).status = tcb.task_status;
        let us = get_time_us() - tcb.task_info.time;
        let tv = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
        let time = ((tv.sec & 0xffff) * 1000 + tv.usec / 1000) as isize;
        (*ti).time = time as usize;
    }
    0
}

/// update syscall times
pub fn update_syscall(syscall_num:usize) {
    let mut lock = task_manager_lock();
    let current_task = lock.current_task;
    let tcb = &mut lock.tasks[current_task];
    tcb.task_info.syscall_times[syscall_num] += 1;
}
