/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 *  \file
 *  \author Victor Julien <victor@inliniac.net>
 *
 * Tracks chunk based file transfers. Chunks may be transfered out
 * of order, but cannot be transfered in parallel. So only one
 * chunk at a time.
 *
 * GAP handling. If a data gap is encountered, the file is truncated
 * and new data is no longer pushed down to the lower level APIs.
 * The tracker does continue to follow the file.
 */

use std::collections::HashMap;
use filecontainer::*;

#[derive(Debug)]
pub struct FileChunk {
    contains_gap: bool,
    chunk: Vec<u8>,
}

impl FileChunk {
    pub fn new(size: u32) -> FileChunk {
        FileChunk {
            contains_gap: false,
            chunk: Vec::with_capacity(size as usize),
        }
    }
}

#[derive(Debug)]
pub struct FileTransferTracker {
    file_size: u64,
    tracked: u64,
    cur_ooo: u64,   // how many bytes do we have queued from ooo chunks
    track_id: u32,
    chunk_left: u32,

    pub tx_id: u64,

    fill_bytes: u8,
    pub file_open: bool,
    chunk_is_last: bool,
    chunk_is_ooo: bool,
    file_is_truncated: bool,

    chunks: HashMap<u64, FileChunk>,
    cur_ooo_chunk_offset: u64,
}

impl FileTransferTracker {
    pub fn new() -> FileTransferTracker {
        FileTransferTracker {
            file_size:0,
            tracked:0,
            cur_ooo:0,
            track_id:0,
            chunk_left:0,
            tx_id:0,
            fill_bytes:0,
            file_open:false,
            chunk_is_last:false,
            chunk_is_ooo:false,
            file_is_truncated:false,
            cur_ooo_chunk_offset:0,
            chunks:HashMap::new(),
        }
    }

    pub fn is_done(&self) -> bool {
        self.file_open == false
    }

    fn open(&mut self, config: &'static SuricataFileContext,
            files: &mut FileContainer, flags: u16, name: &[u8]) -> i32
    {
        0
    }

    pub fn close(&mut self, files: &mut FileContainer, flags: u16) {
    }

    pub fn trunc (&mut self, files: &mut FileContainer, flags: u16) {
    }

    pub fn create(&mut self, name: &[u8], file_size: u64) {
    }

    pub fn new_chunk(&mut self, config: &'static SuricataFileContext,
            files: &mut FileContainer, flags: u16,
            name: &[u8], data: &[u8], chunk_offset: u64, chunk_size: u32,
            fill_bytes: u8, is_last: bool, xid: &u32) -> u32
    {
        0
    }

    /// update the file tracker
    /// If gap_size > 0 'data' should not be used.
    /// return how much we consumed of data
    pub fn update(&mut self, files: &mut FileContainer, flags: u16, data: &[u8], gap_size: u32) -> u32 {
        0
    }

    pub fn get_queued_size(&self) -> u64 {
        0
    }
}
