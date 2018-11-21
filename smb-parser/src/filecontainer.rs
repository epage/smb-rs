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

pub struct SuricataFileContext();

pub struct File;
#[repr(C)]
#[derive(Debug)]
pub struct FileContainer {
}

impl FileContainer {
    pub fn default() -> FileContainer {
        FileContainer {  }
    }
    pub fn free(&mut self) {
    }

    pub fn file_open(&mut self, cfg: &'static SuricataFileContext, track_id: &u32, name: &[u8], flags: u16) -> i32 {
        0
    }

    pub fn file_append(&mut self, track_id: &u32, data: &[u8], is_gap: bool) -> i32 {
        0
    }

    pub fn file_close(&mut self, track_id: &u32, flags: u16) -> i32 {
        0
    }

    pub fn files_prune(&mut self) {
    }

    pub fn file_set_txid_on_last_file(&mut self, tx_id: u64) {
    }
}
